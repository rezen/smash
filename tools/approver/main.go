// Command approver is a Connect RPC reference server for Smash.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"github.com/rezen/smash/gen/smash/approve/v1/approvev1connect"
	"github.com/rezen/smash/internal/approve"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type judge struct {
	allow    bool
	deny     map[string]bool
	logger   *log.Logger
	mu       sync.Mutex
	sessions map[string]bool
}

func (j *judge) log(m proto.Message) {
	b, err := protojson.Marshal(m)
	if err == nil {
		j.logger.Print(string(b))
	}
}
func (j *judge) known(session string) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.sessions[session]
}
func (j *judge) OpenSession(_ context.Context, r *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
	if r.Msg.Version != approve.Version || r.Msg.Session == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("version 1 and session required"))
	}
	j.mu.Lock()
	j.sessions[r.Msg.Session] = true
	j.mu.Unlock()
	j.log(r.Msg)
	return connect.NewResponse(&approvev1.OpenSessionResponse{Version: approve.Version, Audit: true}), nil
}
func (j *judge) Approve(_ context.Context, r *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error) {
	if !j.known(r.Msg.Session) || r.Msg.Command == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("open a session first"))
	}
	j.log(r.Msg)
	allow := j.allow && !j.deny[r.Msg.Command.Name]
	reason := ""
	if !allow {
		reason = "reference server rule"
	}
	return connect.NewResponse(&approvev1.ApproveResponse{Allow: &allow, Reason: reason}), nil
}
func (j *judge) Audit(_ context.Context, stream *connect.ClientStream[approvev1.AuditRequest]) (*connect.Response[approvev1.AuditResponse], error) {
	var count uint64
	for stream.Receive() {
		r := stream.Msg()
		if !j.known(r.Session) {
			return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("unknown session"))
		}
		j.log(r)
		count++
	}
	if err := stream.Err(); err != nil {
		return nil, err
	}
	return connect.NewResponse(&approvev1.AuditResponse{Records: count}), nil
}
func main() {
	addr := flag.String("listen", "127.0.0.1:8787", "listen address")
	allow := flag.Bool("allow-all", false, "allow commands except explicitly denied names")
	denied := flag.String("deny", "", "comma-separated command names to deny")
	logfile := flag.String("log", "-", "JSON log destination (- = stderr)")
	flag.Parse()
	logger := log.New(os.Stderr, "", 0)
	if *logfile != "-" {
		f, err := os.OpenFile(*logfile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		logger.SetOutput(f)
	}
	deny := map[string]bool{}
	for _, name := range strings.Split(*denied, ",") {
		deny[strings.TrimSpace(name)] = true
	}
	j := &judge{allow: *allow, deny: deny, logger: logger, sessions: map[string]bool{}}
	mux := http.NewServeMux()
	path, handler := approvev1connect.NewApprovalServiceHandler(j)
	mux.Handle(path, handler)
	server := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}

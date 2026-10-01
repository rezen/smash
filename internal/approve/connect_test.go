package approve

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"github.com/rezen/smash/gen/smash/approve/v1/approvev1connect"
	"github.com/rezen/smash/internal/sandbox"
	"google.golang.org/protobuf/proto"
	"mvdan.cc/sh/v3/interp"
)

type testJudge struct {
	approvev1connect.UnimplementedApprovalServiceHandler
	open  func(context.Context, *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error)
	ask   func(context.Context, *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error)
	audit func(context.Context, *connect.ClientStream[approvev1.AuditRequest]) (*connect.Response[approvev1.AuditResponse], error)
}

func (j testJudge) OpenSession(c context.Context, r *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
	if j.open != nil {
		return j.open(c, r)
	}
	return connect.NewResponse(&approvev1.OpenSessionResponse{Version: Version}), nil
}
func (j testJudge) Approve(c context.Context, r *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error) {
	if j.ask != nil {
		return j.ask(c, r)
	}
	return connect.NewResponse(&approvev1.ApproveResponse{Allow: proto.Bool(true)}), nil
}
func (j testJudge) Audit(c context.Context, s *connect.ClientStream[approvev1.AuditRequest]) (*connect.Response[approvev1.AuditResponse], error) {
	if j.audit != nil {
		return j.audit(c, s)
	}
	for s.Receive() {
	}
	return connect.NewResponse(&approvev1.AuditResponse{}), s.Err()
}
func server(t *testing.T, j testJudge) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, h := approvev1connect.NewApprovalServiceHandler(j)
	mux.Handle(path, h)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}
func dial(t *testing.T, s *httptest.Server, o Options) *Client {
	t.Helper()
	if o.Timeout == 0 {
		o.Timeout = time.Second
	}
	c, err := Dial(context.Background(), s.URL, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func TestConnectSessionAndConcurrentDecisions(t *testing.T) {
	var seen atomic.Int32
	firstArrived := make(chan struct{})
	secondArrived := make(chan struct{})
	j := testJudge{
		open: func(_ context.Context, r *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
			if r.Msg.Version != Version || r.Msg.Session == "" || r.Msg.Pid == 0 || r.Msg.Root != "/root" || !r.Msg.Interactive {
				t.Errorf("hello: %v", r.Msg)
			}
			return connect.NewResponse(&approvev1.OpenSessionResponse{Version: Version, TimeoutMs: 45000}), nil
		},
		ask: func(ctx context.Context, r *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error) {
			seen.Add(1)
			if r.Msg.Session == "" || r.Msg.Id == "" || r.Msg.Dir != "/work" {
				t.Errorf("request: %v", r.Msg)
			}
			if r.Msg.Command.Name == "first" {
				close(firstArrived)
				select {
				case <-secondArrived:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			} else {
				close(secondArrived)
			}
			return connect.NewResponse(&approvev1.ApproveResponse{Allow: proto.Bool(r.Msg.Command.Name == "second"), Reason: r.Msg.Command.Name, Remember: approvev1.Remember_REMEMBER_NAME}), nil
		},
	}
	c := dial(t, server(t, j), Options{Hello: &approvev1.OpenSessionRequest{Root: "/root", Interactive: true}})
	if c.Timeout() != 45*time.Second {
		t.Fatal(c.Timeout())
	}
	done := make(chan sandbox.Decision, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		d, err := c.Approve(ctx, sandbox.ApprovalRequest{Name: "first", Dir: "/work"})
		if err != nil {
			t.Error(err)
		}
		done <- d
	}()
	select {
	case <-firstArrived:
	case <-ctx.Done():
		t.Fatal("first did not arrive")
	}
	d, err := c.Approve(ctx, sandbox.ApprovalRequest{Name: "second", Dir: "/work"})
	if err != nil || !d.Allow || d.Remember != sandbox.RememberName {
		t.Fatalf("decision=%+v err=%v", d, err)
	}
	select {
	case d := <-done:
		if d.Allow || d.Reason != "first" {
			t.Fatal(d)
		}
	case <-ctx.Done():
		t.Fatal("first hung")
	}
	if seen.Load() != 2 {
		t.Fatal(seen.Load())
	}
}
func TestConnectFailureClosed(t *testing.T) {
	for _, tt := range []struct {
		name     string
		response *approvev1.ApproveResponse
		rpcErr   error
	}{
		{"missing allow", &approvev1.ApproveResponse{}, nil},
		{"bad remember", &approvev1.ApproveResponse{Allow: proto.Bool(true), Remember: 99}, nil},
		{"unavailable", nil, connect.NewError(connect.CodeUnavailable, errors.New("lost"))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var count atomic.Int32
			c := dial(t, server(t, testJudge{ask: func(context.Context, *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error) {
				count.Add(1)
				if tt.rpcErr != nil {
					return nil, tt.rpcErr
				}
				return connect.NewResponse(tt.response), nil
			}}), Options{})
			if d, err := c.Approve(context.Background(), sandbox.ApprovalRequest{}); err == nil || d.Allow {
				t.Fatalf("%+v %v", d, err)
			}
			if _, err := c.Approve(context.Background(), sandbox.ApprovalRequest{}); !errors.Is(err, ErrDisconnected) {
				t.Fatal(err)
			}
			if count.Load() != 1 {
				t.Fatal(count.Load())
			}
		})
	}
	s := server(t, testJudge{})
	c := dial(t, s, Options{})
	s.Close()
	if _, err := c.Approve(context.Background(), sandbox.ApprovalRequest{}); err == nil {
		t.Fatal("closed server allowed")
	}
	if _, err := c.Approve(context.Background(), sandbox.ApprovalRequest{}); !errors.Is(err, ErrDisconnected) {
		t.Fatal(err)
	}
}
func TestConnectDeadline(t *testing.T) {
	c := dial(t, server(t, testJudge{ask: func(ctx context.Context, _ *connect.Request[approvev1.ApproveRequest]) (*connect.Response[approvev1.ApproveResponse], error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}), Options{Timeout: 50 * time.Millisecond})
	start := time.Now()
	if d, err := c.Approve(context.Background(), sandbox.ApprovalRequest{}); err == nil || d.Allow {
		t.Fatalf("%v %v", d, err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("decision timeout ignored")
	}
}
func TestConnectAudit(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{true: "enabled", false: "disabled"}[enabled], func(t *testing.T) {
			var mu sync.Mutex
			var records []*approvev1.AuditRecord
			s := server(t, testJudge{
				open: func(context.Context, *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
					return connect.NewResponse(&approvev1.OpenSessionResponse{Version: Version, Audit: enabled}), nil
				},
				audit: func(_ context.Context, stream *connect.ClientStream[approvev1.AuditRequest]) (*connect.Response[approvev1.AuditResponse], error) {
					for stream.Receive() {
						mu.Lock()
						records = append(records, proto.Clone(stream.Msg().Record).(*approvev1.AuditRecord))
						mu.Unlock()
					}
					return connect.NewResponse(&approvev1.AuditResponse{}), stream.Err()
				},
			})
			c := dial(t, s, Options{})
			sink := AuditSink{Client: c}
			sink.Audit(sandbox.AuditRecord{Name: "rm", Exit: interp.ExitStatus(126), Reason: "denied", Served: "approve", Duration: 2 * time.Millisecond})
			sink.AuditOpen(sandbox.OpenRecord{Path: "x", Op: sandbox.OpenWrite})
			c.Close()
			mu.Lock()
			defer mu.Unlock()
			if !enabled {
				if len(records) != 0 {
					t.Fatal(records)
				}
				return
			}
			if len(records) != 2 || records[0].Exit != 126 || records[0].DurationMs != 2 || records[1].Name != "shell" {
				t.Fatalf("records=%v", records)
			}
		})
	}
}
func TestConnectHeadersAndTLS(t *testing.T) {
	t.Setenv("SMASH_APPROVE_TOKEN", "env-token")
	for _, header := range []string{"", "literal-token"} {
		expected := "Bearer env-token"
		headers := http.Header{}
		if header != "" {
			headers["authorization"] = []string{header}
			expected = header
		}
		s := server(t, testJudge{open: func(_ context.Context, r *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
			if r.Header().Get("Authorization") != expected {
				t.Error(r.Header())
			}
			return connect.NewResponse(&approvev1.OpenSessionResponse{Version: Version}), nil
		}})
		dial(t, s, Options{Headers: headers})
	}
	mux := http.NewServeMux()
	p, h := approvev1connect.NewApprovalServiceHandler(testJudge{})
	mux.Handle(p, h)
	tls := httptest.NewTLSServer(mux)
	defer tls.Close()
	if _, err := Dial(context.Background(), tls.URL, Options{Timeout: time.Second}); err == nil {
		t.Fatal("untrusted TLS accepted")
	}
	c, err := Dial(context.Background(), tls.URL, Options{HTTPClient: tls.Client()})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
func TestConnectInvalidWelcome(t *testing.T) {
	for _, w := range []*approvev1.OpenSessionResponse{{Version: 2}, {Version: 1, TimeoutMs: -1}} {
		s := server(t, testJudge{open: func(context.Context, *connect.Request[approvev1.OpenSessionRequest]) (*connect.Response[approvev1.OpenSessionResponse], error) {
			return connect.NewResponse(w), nil
		}})
		if _, err := Dial(context.Background(), s.URL, Options{}); err == nil {
			t.Fatal("invalid welcome accepted")
		}
	}
}
func TestPrompt(t *testing.T) {
	for _, tt := range []struct {
		answer   string
		allow    bool
		remember sandbox.Remember
	}{{"y", true, 0}, {"n", false, 0}, {"", false, 0}, {"a", true, sandbox.RememberName}} {
		var out strings.Builder
		p := NewPrompt(strings.NewReader(tt.answer+"\n"), &out)
		d, err := p.Approve(context.Background(), sandbox.ApprovalRequest{Line: "ls", Verdict: sandbox.VerdictAllowed})
		if err != nil || d.Allow != tt.allow || d.Remember != tt.remember || !strings.Contains(out.String(), "[y/N/a]") {
			t.Fatalf("%+v %v %q", d, err, out.String())
		}
	}
}
func TestPromptCancelledAnswerCannotApproveNext(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	p := NewPrompt(r, io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := p.Approve(ctx, sandbox.ApprovalRequest{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	done := make(chan sandbox.Decision, 1)
	go func() { d, _ := p.Approve(context.Background(), sandbox.ApprovalRequest{}); done <- d }()
	io.WriteString(w, "y\nn\n")
	select {
	case d := <-done:
		if d.Allow {
			t.Fatal("stale y approved next command")
		}
	case <-time.After(time.Second):
		t.Fatal("prompt hung")
	}
}

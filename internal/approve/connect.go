package approve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"github.com/rezen/smash/gen/smash/approve/v1/approvev1connect"
	"github.com/rezen/smash/internal/sandbox"
)

var ErrDisconnected = errors.New("approver disconnected")

type Options struct {
	Headers    http.Header
	Timeout    time.Duration
	Hello      *approvev1.OpenSessionRequest
	HTTPClient *http.Client
	Stderr     io.Writer
}

// Client calls the generated Connect client. Concurrent decisions have separate
// RPCs; a failed transport permanently closes this session, without retrying.
type Client struct {
	rpc       approvev1connect.ApprovalServiceClient
	timeout   time.Duration
	audit     bool
	session   string
	headers   http.Header
	mu        sync.Mutex
	next      uint64
	err       error
	stderr    io.Writer
	ctx       context.Context
	cancel    context.CancelFunc
	audits    chan *approvev1.AuditRecord
	auditDone chan struct{}
	closeOnce sync.Once
	closing   bool
}

// Dial performs OpenSession within the configured handshake timeout. Successful
// sessions outlive ctx; Close releases the optional audit stream.
func Dial(ctx context.Context, address string, o Options) (*Client, error) {
	u, err := url.Parse(address)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("approve: expected an http:// or https:// Connect base URL without credentials, query or fragment")
	}
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	headers := make(http.Header)
	for k, vs := range o.Headers {
		for _, v := range vs {
			headers.Add(k, v)
		}
	}
	if _, ok := headers["Authorization"]; !ok {
		if token := os.Getenv("SMASH_APPROVE_TOKEN"); token != "" {
			headers.Set("Authorization", "Bearer "+token)
		}
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
	} else {
		cp := *client
		client = &cp
	}
	// Do not forward credentials or approval requests to HTTP redirect targets.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	rpc := approvev1connect.NewApprovalServiceClient(client, address)
	h := &approvev1.OpenSessionRequest{}
	if o.Hello != nil {
		h.Version = o.Hello.Version
		h.Session = o.Hello.Session
		h.User = o.Hello.User
		h.Host = o.Hello.Host
		h.Root = o.Hello.Root
		h.Mode = o.Hello.Mode
		h.Interactive = o.Hello.Interactive
	}
	h.Version = Version
	h.Pid = int64(os.Getpid())
	if h.Session == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		h.Session = hex.EncodeToString(b)
	}
	if h.Host == "" {
		h.Host, _ = os.Hostname()
	}
	if h.User == "" {
		if u, err := user.Current(); err == nil {
			h.User = u.Username
		}
	}
	req := connect.NewRequest(h)
	copyHeaders(req.Header(), headers)
	welcome, err := rpc.OpenSession(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("approve OpenSession: %w", err)
	}
	w := welcome.Msg
	if w.Version != Version {
		return nil, errors.New("approve: unsupported protocol version")
	}
	if w.TimeoutMs < 0 || w.TimeoutMs > math.MaxInt64/int64(time.Millisecond) {
		return nil, errors.New("approve: invalid decision timeout")
	}
	if w.TimeoutMs > 0 {
		o.Timeout = time.Duration(w.TimeoutMs) * time.Millisecond
	}
	lifetime, stop := context.WithCancel(context.Background())
	c := &Client{rpc: rpc, timeout: o.Timeout, audit: w.Audit, session: h.Session, headers: headers, stderr: o.Stderr, ctx: lifetime, cancel: stop, audits: make(chan *approvev1.AuditRecord, 256), auditDone: make(chan struct{})}
	if c.audit {
		go c.auditLoop()
	} else {
		close(c.auditDone)
	}
	return c, nil
}
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
}
func (c *Client) Timeout() time.Duration { return c.timeout }
func (c *Client) AuditEnabled() bool     { return c.audit }

// ApprovalError reports whether this session's RPC transport is still usable.
// The sandbox checks it before serving remembered decisions so a disconnected
// supervisor cannot leave cached grants active.
func (c *Client) ApprovalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	if c.closing {
		return ErrDisconnected
	}
	return nil
}

func (c *Client) disconnect(err error, notice bool) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = fmt.Errorf("%w: %v", ErrDisconnected, err)
	c.cancel()
	c.mu.Unlock()
	if notice && c.stderr != nil {
		fmt.Fprintln(c.stderr, "[smash] approver disconnected; subsequent commands will be denied")
	}
}
func (c *Client) Approve(ctx context.Context, req sandbox.ApprovalRequest) (sandbox.Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	c.mu.Lock()
	if c.err != nil || c.closing {
		err := c.err
		if err == nil {
			err = ErrDisconnected
		}
		c.mu.Unlock()
		return sandbox.Decision{}, err
	}
	c.next++
	id := strconv.FormatUint(c.next, 10)
	c.mu.Unlock()
	call := connect.NewRequest(&approvev1.ApproveRequest{Session: c.session, Id: id, Dir: req.Dir, Command: requestCommand(req)})
	copyHeaders(call.Header(), c.headers)
	response, err := c.rpc.Approve(ctx, call)
	if err != nil {
		// A deadline or caller cancellation denies just this request. Transport
		// and protocol failures invalidate the session and all in-flight requests.
		if ctx.Err() == nil && connect.CodeOf(err) != connect.CodeDeadlineExceeded && connect.CodeOf(err) != connect.CodeCanceled {
			c.disconnect(err, true)
		}
		return sandbox.Decision{}, err
	}
	r := response.Msg
	if r.Allow == nil || r.Remember < approvev1.Remember_REMEMBER_UNSPECIFIED || r.Remember > approvev1.Remember_REMEMBER_NAME {
		err := errors.New("malformed approval decision")
		c.disconnect(err, true)
		return sandbox.Decision{}, err
	}
	return sandbox.Decision{Allow: *r.Allow, Reason: r.Reason, Remember: sandbox.Remember(r.Remember)}, nil
}

// Close drains audit records and half-closes the stream. A stalled peer gets
// at most one second to acknowledge before the session is cancelled.
func (c *Client) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		close(c.audits)
		c.mu.Unlock()
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		select {
		case <-c.auditDone:
		case <-timer.C:
		}
		c.disconnect(errors.New("closed"), false)
	})
	return nil
}

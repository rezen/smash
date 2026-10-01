package approve

import (
	"errors"

	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"github.com/rezen/smash/internal/sandbox"
)

// AuditSink forwards already-redacted records only when OpenSession requested
// them. A bounded queue keeps command execution independent of network writes.
// Queue overflow disconnects rather than silently dropping audit evidence.
type AuditSink struct{ Client *Client }

func (s AuditSink) Audit(r sandbox.AuditRecord) { s.Client.enqueue(auditRecord(r)) }
func (s AuditSink) AuditOpen(r sandbox.OpenRecord) {
	res := r.Resource()
	d := &approvev1.AuditRecord{Name: "shell", Resources: []*approvev1.Resource{{Kind: res.Kind, Action: res.Action, Value: res.Value}}}
	if f, ok := r.Change(); ok {
		d.Files = []*approvev1.FileChange{{Op: string(f.Op), Path: f.Path}}
	}
	if r.Err != nil {
		d.Error = r.Err.Error()
		d.Exit = 1
	}
	s.Client.enqueue(d)
}
func (c *Client) enqueue(v *approvev1.AuditRecord) {
	if !c.audit {
		return
	}
	c.mu.Lock()
	if c.err != nil || c.closing {
		c.mu.Unlock()
		return
	}
	select {
	case c.audits <- v:
		c.mu.Unlock()
	default:
		c.mu.Unlock()
		c.disconnect(errors.New("audit queue full"), true)
	}
}
func (c *Client) auditLoop() {
	defer close(c.auditDone)
	stream := c.rpc.Audit(c.ctx)
	copyHeaders(stream.RequestHeader(), c.headers)
	for {
		select {
		case <-c.ctx.Done():
			return
		case record, ok := <-c.audits:
			if !ok {
				if _, err := stream.CloseAndReceive(); err != nil {
					c.disconnect(err, true)
				}
				return
			}
			if err := stream.Send(&approvev1.AuditRequest{Session: c.session, Record: record}); err != nil {
				c.disconnect(err, true)
				return
			}
		}
	}
}

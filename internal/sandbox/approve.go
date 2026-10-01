package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/rezen/smash/internal/command"
	"mvdan.cc/sh/v3/interp"
)

// Approver can narrow local permission. Approve may be called concurrently.
type Approver interface {
	Approve(context.Context, ApprovalRequest) (Decision, error)
}
type ApproverFunc func(context.Context, ApprovalRequest) (Decision, error)

func (f ApproverFunc) Approve(ctx context.Context, req ApprovalRequest) (Decision, error) {
	return f(ctx, req)
}

type ApprovalRequest struct {
	Name      string               `json:"name"`
	Argv      []string             `json:"argv"`
	Line      string               `json:"line"`
	Wrappers  []string             `json:"wrappers"`
	Resources []command.Resource   `json:"resources"`
	Egress    *command.Egress      `json:"egress"`
	Files     []command.FileChange `json:"files"`
	Dir       string               `json:"-"`
	Verdict   Verdict              `json:"verdict"`
}
type Remember int

const (
	RememberNone Remember = iota
	RememberArgv
	RememberName
)

type Decision struct {
	Allow    bool
	Reason   string
	Remember Remember
}

type decisionCache struct {
	mu    sync.Mutex
	names map[string]Decision
	argv  map[string]Decision
}

func (c *decisionCache) get(name, key string) (Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d, ok := c.argv[key]; ok {
		return d, true
	}
	d, ok := c.names[name]
	return d, ok
}
func (c *decisionCache) put(name, key string, d Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch d.Remember {
	case RememberName:
		c.names[name] = d
	case RememberArgv:
		c.argv[key] = d
	}
}

// TerminalText escapes terminal controls while keeping ordinary text readable.
func TerminalText(s string) string { q := strconv.Quote(s); return q[1 : len(q)-1] }

func approveMiddleware(cfg Config) Middleware {
	g := configGate(cfg)
	cache := &decisionCache{names: map[string]Decision{}, argv: map[string]Decision{}}
	timeout := cfg.ApproveTimeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if driver, _ := ctx.Value(iterationDriverKey{}).(bool); driver || len(args) == 0 {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			verdict, path := g.judge(hc, args)
			p := parsedFrom(ctx, args)
			// These handlers serve commands before the gate. Even when the gate
			// would reject a host invocation, the confined implementation needs approval.
			served := p.Name == "curl" || p.Name == "wget" || p.Name == "mktemp" || p.Name == "sha256sum" || p.Name == "base64" || p.Name == "sleep" || (p.Name == "uname" && cfg.Emulation.UnameOS != "")
			if sr, ok := p.Command().(command.ScriptRunner); ok {
				_, _, served = sr.DashC(args)
			}
			if p.Name == "git" && len(args) == 2 && args[1] == "--version" && resolveHostCommandPath(cfg, "git") != "" {
				served = true
			}
			blocked := verdict == VerdictSensitiveBlocked || verdict == VerdictStrictBlocked || verdict == VerdictDisabledBlocked || (verdict == VerdictInRootNative && !cfg.AllowInRootExecutables) || (verdict == VerdictAllowed && path == "")
			if !cfg.Profile && blocked && !served {
				return next(ctx, args)
			}
			params := command.Redact(p.TypedParams())
			req := ApprovalRequest{Name: p.Name, Argv: params.Args(), Line: params.String(), Wrappers: wrappersFrom(ctx), Resources: command.RedactResources(p.Resources()), Files: p.FileChanges(), Dir: hc.Dir, Verdict: verdict}
			for i := range req.Files {
				req.Files[i].Path = command.RedactURL(req.Files[i].Path)
				req.Files[i].From = command.RedactURL(req.Files[i].From)
			}
			if e, ok := p.EgressInfo(); ok {
				e.Target = command.RedactURL(e.Target)
				req.Egress = &e
			}
			if status, ok := cfg.Approver.(interface{ ApprovalError() error }); ok {
				if err := status.ApprovalError(); err != nil {
					return failf(hc.Stderr, 126, "[sandbox] denied by approver: %s", TerminalText(err.Error()))
				}
			}
			// Exact original argv is the cache identity: normalization and redaction
			// must not cause two different commands or credentials to share a grant.
			keyBytes, _ := json.Marshal(args)
			key := string(keyBytes)
			d, cached := cache.get(req.Name, key)
			if !cached {
				fmt.Fprintf(hc.Stderr, "[sandbox] awaiting approval: %s\n", TerminalText(req.Line))
				askCtx, cancel := context.WithTimeout(ctx, timeout)
				var err error
				d, err = cfg.Approver.Approve(askCtx, req)
				if err == nil {
					err = askCtx.Err()
				}
				cancel()
				if err != nil {
					return failf(hc.Stderr, 126, "[sandbox] denied by approver: %s", TerminalText(err.Error()))
				}
				cache.put(req.Name, key, d)
			}
			if !d.Allow {
				reason := d.Reason
				if reason == "" {
					reason = "permission refused"
				}
				return failf(hc.Stderr, 126, "[sandbox] denied by approver: %s", TerminalText(reason))
			}
			return next(ctx, args)
		}
	}
}

package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezen/smash/internal/command"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
)

func TestApprovalDecisions(t *testing.T) {
	for _, tt := range []struct {
		name     string
		decision Decision
		err      error
		timeout  bool
		want     int
	}{
		{name: "allow", decision: Decision{Allow: true}},
		{name: "deny", decision: Decision{Reason: "no\x1b[2J"}, want: 126},
		{name: "error", err: errors.New("offline"), want: 126},
		{name: "timeout", timeout: true, want: 126},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var rec AuditRecord
			_, stderr, err := runConfined(t, "/usr/bin/true", func(cfg *Config) {
				cfg.Auditor = AuditorFunc(func(r AuditRecord) { rec = r })
				cfg.ApproveTimeout = 10 * time.Millisecond
				cfg.Approver = ApproverFunc(func(ctx context.Context, req ApprovalRequest) (Decision, error) {
					if req.Name != "true" || req.Dir == "" || req.Verdict != VerdictAllowed {
						t.Errorf("request: %+v", req)
					}
					if tt.timeout {
						<-ctx.Done()
						return Decision{}, ctx.Err()
					}
					return tt.decision, tt.err
				})
			})
			code, _ := exitCode(err)
			if code != tt.want || !strings.Contains(stderr, "awaiting approval") {
				t.Fatalf("err=%v stderr=%s", err, stderr)
			}
			if tt.want != 0 && (rec.Served != "approve" || rec.Reason == "" || strings.Contains(stderr, "\x1b")) {
				t.Fatalf("record=%+v stderr=%q", rec, stderr)
			}
		})
	}
}
func TestApprovalLocalPolicy(t *testing.T) {
	for _, tt := range []struct {
		name, src string
		monitor   bool
		count     int
		ok        bool
	}{
		{"sensitive", "python3 -c pass", false, 0, false},
		{"monitor sensitive", "python3 -c pass", true, 1, false}, // denied by judge
		{"shell", "sh -c '/usr/bin/true'", false, 1, false},
		{"mock", "fake", false, 0, true},
		{"disabled", "rm x", false, 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			asked := 0
			_, _, err := runConfined(t, tt.src, func(cfg *Config) {
				cfg.Profile = tt.monitor
				cfg.Disable("rm")
				cfg.Mock(MatchName("fake"), "", "", 0)
				cfg.Approver = ApproverFunc(func(context.Context, ApprovalRequest) (Decision, error) { asked++; return Decision{}, nil })
			})
			if asked != tt.count || (err == nil) != tt.ok {
				t.Fatalf("asked=%d err=%v", asked, err)
			}
		})
	}
	_, _, err := runConfined(t, "curl https://forbidden.invalid/", func(cfg *Config) {
		cfg.Approver = ApproverFunc(func(context.Context, ApprovalRequest) (Decision, error) { return Decision{Allow: true}, nil })
	})
	if err == nil {
		t.Fatal("approval widened network policy")
	}
}
func TestApprovalRememberAndConcurrency(t *testing.T) {
	for _, remember := range []Remember{RememberName, RememberArgv} {
		asked := 0
		_, _, err := runConfined(t, "/usr/bin/true; /usr/bin/true", func(cfg *Config) {
			cfg.Approver = ApproverFunc(func(context.Context, ApprovalRequest) (Decision, error) {
				asked++
				return Decision{Allow: true, Remember: remember}, nil
			})
		})
		if err != nil || asked != 1 {
			t.Fatalf("asked=%d err=%v", asked, err)
		}
	}
	var mu sync.Mutex
	var requests []ApprovalRequest
	_, _, err := runConfined(t, "printf x | cat | cat | cat", func(cfg *Config) {
		cfg.Approver = ApproverFunc(func(_ context.Context, r ApprovalRequest) (Decision, error) {
			mu.Lock()
			requests = append(requests, r)
			mu.Unlock()
			return Decision{Allow: true}, nil
		})
	})
	if err != nil || len(requests) != 3 {
		t.Fatalf("requests=%v err=%v", requests, err)
	}
}
func TestApprovalIterationAndRedaction(t *testing.T) {
	var reqs []ApprovalRequest
	_, _, err := runConfined(t, "printf 'x\\ny\\n' | xargs -n1 /usr/bin/true", func(cfg *Config) {
		cfg.Approver = ApproverFunc(func(_ context.Context, r ApprovalRequest) (Decision, error) {
			reqs = append(reqs, r)
			return Decision{Allow: true}, nil
		})
	})
	if err != nil || len(reqs) != 2 {
		t.Fatalf("reqs=%v err=%v", reqs, err)
	}
	for _, r := range reqs {
		if r.Name != "true" {
			t.Fatal(r.Name)
		}
	}
	_, _, err = runConfined(t, "curl -H 'Authorization: secret' https://user:pass@example.com", func(cfg *Config) {
		cfg.Approver = ApproverFunc(func(_ context.Context, r ApprovalRequest) (Decision, error) {
			if strings.Contains(r.Line, "secret") || strings.Contains(strings.Join(r.Argv, " "), "pass@") {
				t.Errorf("leaked: %+v", r)
			}
			return Decision{}, nil
		})
	})
	if !errors.Is(err, interp.ExitStatus(126)) {
		t.Fatal(err)
	}
}

func TestGateJudge(t *testing.T) {
	root := t.TempDir()
	scripts := map[string]string{
		"shell":      "#!/bin/sh\ntrue\n",
		"cat-script": "#!/bin/cat\n",
		"python":     "#!/usr/bin/python3\npass\n",
		"denied":     "#!/usr/bin/disabled\n",
	}
	for name, src := range scripts {
		if err := os.WriteFile(filepath.Join(root, name), []byte(src), 0755); err != nil {
			t.Fatal(err)
		}
	}
	native := filepath.Join(root, "native")
	if err := os.WriteFile(native, []byte("native"), 0755); err != nil {
		t.Fatal(err)
	}
	hc := interp.HandlerContext{Dir: root, Env: expand.ListEnviron("PATH=" + root)}
	g := gate{registry: command.Default, root: root, allowed: DefaultAllowList().With("ls"), sensitive: DefaultSensitiveList().With("python3"), denied: command.NewSet("disabled"), strict: true, allowedPaths: map[string]string{"ls": "/bin/ls"}, interpret: func(context.Context, interp.HandlerContext, string, []string, bool) error { return nil }}
	cases := []struct {
		name string
		args []string
		want Verdict
	}{
		{"allowed", []string{"ls"}, VerdictAllowed},
		{"missing-allowed", []string{"not-installed"}, VerdictStrictBlocked},
		{"sensitive", []string{"python3"}, VerdictSensitiveBlocked},
		{"strict", []string{"df"}, VerdictStrictBlocked},
	}
	for _, tc := range cases {
		got, _ := g.judge(hc, tc.args)
		if got != tc.want {
			t.Errorf("%s: %s want %s", tc.name, got, tc.want)
		}
	}
	for file, want := range map[string]Verdict{"shell": VerdictInRootScript, "cat-script": VerdictInRootInterpreter, "python": VerdictSensitiveBlocked, "denied": VerdictDisabledBlocked, "native": VerdictInRootNative} {
		got, _ := g.judge(hc, []string{filepath.Join(root, file)})
		if got != want {
			t.Errorf("%s: %s want %s", file, got, want)
		}
	}
	g.allowInRootExecutables = true
	if got, _ := g.judge(hc, []string{native}); got != VerdictInRootNative {
		t.Fatal(got)
	}
}

type healthApprover struct {
	mu           sync.Mutex
	disconnected bool
}

func (a *healthApprover) Approve(context.Context, ApprovalRequest) (Decision, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.disconnected = true
	return Decision{Allow: true, Remember: RememberName}, nil
}
func (a *healthApprover) ApprovalError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.disconnected {
		return errors.New("approver disconnected")
	}
	return nil
}
func TestRememberedGrantExpiresOnDisconnect(t *testing.T) {
	a := &healthApprover{}
	_, stderr, err := runConfined(t, "/usr/bin/true; /usr/bin/true", func(cfg *Config) { cfg.Approver = a })
	if !errors.Is(err, interp.ExitStatus(126)) || !strings.Contains(stderr, "denied by approver: approver disconnected") {
		t.Fatalf("err=%v stderr=%q", err, stderr)
	}
}

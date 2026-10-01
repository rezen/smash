package sandbox

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

func sessionRun(t *testing.T, s *Session, src string) error {
	t.Helper()
	p, err := syntax.NewParser().Parse(strings.NewReader(src), "test")
	if err != nil {
		t.Fatal(err)
	}
	return s.Run(context.Background(), p.Stmts)
}
func TestSessionState(t *testing.T) {
	root := t.TempDir()
	var out lockedBuffer
	records := 0
	cfg := NewConfig(root, root, expand.ListEnviron(hostPath))
	cfg.Timeout = 0
	cfg.Interactive = true
	cfg.Stdout = &out
	cfg.Stderr = &out
	cfg.Auditor = AuditorFunc(func(AuditRecord) { records++ })
	s, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{"x=1; f() { echo function:$x; }; alias hi='echo alias'; mkdir sub", "echo $x; f; hi; cd sub", "pwd; /usr/bin/true"} {
		if err := sessionRun(t, s, src); err != nil {
			t.Fatal(err)
		}
	}
	if got := out.String(); !strings.Contains(got, "1\nfunction:1\nalias\n"+root+"/sub\n") {
		t.Fatal(got)
	}
	if s.Vars()["x"].String() != "1" || records != 2 || s.cfg.Timeout != 0 {
		t.Fatalf("vars=%v records=%d timeout=%v", s.Vars(), records, s.cfg.Timeout)
	}
	err = sessionRun(t, s, "exit 3")
	if !s.Exited() || !errors.Is(err, interp.ExitStatus(3)) {
		t.Fatalf("exited=%v err=%v", s.Exited(), err)
	}
}
func TestSessionTimeoutRecovery(t *testing.T) {
	cfg := NewConfig(t.TempDir(), ".", expand.ListEnviron(hostPath))
	cfg.Timeout = 20 * time.Millisecond
	s, err := NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sessionRun(t, s, "sleep 30"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	if err := sessionRun(t, s, "x=after; true"); err != nil {
		t.Fatal(err)
	}
	if s.Vars()["x"].String() != "after" {
		t.Fatal("state lost")
	}
}

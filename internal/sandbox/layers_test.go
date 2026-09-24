package sandbox

// The exec middleware ORDER is the enforcement contract (see execLayers).
// These tests pin it by layer name so a reorder is a conscious, reviewed
// change here rather than a silent one in buildRunner.

import (
	"os"
	"slices"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

// everythingOnConfig turns every optional layer on.
func everythingOnConfig(t *testing.T) Config {
	t.Helper()
	cfg := NewConfig(t.TempDir(), ".", expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Auditor = AuditorFunc(func(AuditRecord) {})
	cfg.Disable("frobnicate")
	cfg.AllowSudo = true
	cfg.Mock(MatchName("frobnicate"), "", "", 0)
	cfg.Emulation = Emulation{UnameOS: "Linux"}
	cfg.ControllingTTY = os.Stdout
	return cfg
}

func layerNames(t *testing.T, cfg Config) []string {
	t.Helper()
	s, err := execLayers(cfg.normalized())
	if err != nil {
		t.Fatalf("execLayers: %v", err)
	}
	return s.names
}

func TestExecLayerOrdering(t *testing.T) {
	names := layerNames(t, everythingOnConfig(t))
	want := []string{
		"unwrap", "audit", "deny", "sudo-grant", "mock",
		"git-version", "sleep-cap",
		"sh-interp", "tool-mktemp", "tool-sha256sum", "tool-base64", "uname",
		"http", "egress", "gate", "tty",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("exec stack order changed:\n got  %v\n want %v", names, want)
	}

	// The individual invariants, with the reason each one exists. Implied by
	// the exact order above, but a failure here says WHY the order matters.
	mustPrecede := func(a, b, why string) {
		t.Helper()
		ia, ib := slices.Index(names, a), slices.Index(names, b)
		if ia < 0 || ib < 0 || ia >= ib {
			t.Errorf("%q must precede %q: %s", a, b, why)
		}
	}
	if names[0] != "unwrap" {
		t.Errorf("unwrap must be outermost: every guard has to see the real command behind sudo/env/xargs/…")
	}
	mustPrecede("audit", "deny", "the audit record must carry the true outcome of every enforcement layer")
	mustPrecede("deny", "sudo-grant", "-disable sudo must beat AllowSudo's grant")
	mustPrecede("deny", "mock", "a disabled command cannot be mocked back to life")
	mustPrecede("mock", "http", "a mocked curl must never touch the network")
	mustPrecede("http", "egress", "curl/wget are served in-process before the generic egress guard")
	mustPrecede("egress", "gate", "network-capable commands are judged by intent before the name gate runs them")
	mustPrecede("sh-interp", "gate", "`sh -c` must be re-interpreted confined, not judged (and run) as a shell binary")
}

// TestProfileModeLayers pins profile mode's carve-out: it observes without
// enforcing, so the observation layers remain — including http, which under
// profile is the observe-only downloader (everything admitted), so discovery
// exercises the same in-process implementation enforcement will use.
func TestProfileModeLayers(t *testing.T) {
	cfg := everythingOnConfig(t)
	cfg.Profile = true
	names := layerNames(t, cfg)
	want := []string{
		"unwrap", "audit", "sudo-grant",
		"sh-interp", "tool-mktemp", "tool-sha256sum", "tool-base64", "uname", "http", "tty",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("profile-mode stack changed:\n got  %v\n want %v", names, want)
	}
}

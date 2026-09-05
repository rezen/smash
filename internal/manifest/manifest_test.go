package manifest

import (
	"runtime"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/sandbox"
)

func TestProfilerBuildsStableManifest(t *testing.T) {
	p := NewProfiler("install.sh", "echo hello\n", nil)
	p.Audit(sandbox.AuditRecord{
		Name: "curl",
		Resources: []command.Resource{
			{Kind: "url", Action: "fetch", Value: "https://Downloads.Example.test/tool"},
		},
	})
	p.Audit(sandbox.AuditRecord{Name: "uname"})
	p.Audit(sandbox.AuditRecord{Name: "curl"})
	p.Audit(sandbox.AuditRecord{
		Name: "git",
		Resources: []command.Resource{
			{Kind: "repo", Action: "clone", Value: "git@github.com:owner/repo.git"},
		},
	})
	m := p.Manifest()
	if m.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", m.OS, runtime.GOOS)
	}
	if got := strings.Join(m.Commands, ","); got != "curl,git,uname" {
		t.Errorf("commands = %s", got)
	}
	if got := strings.Join(m.Hosts, ","); got != "downloads.example.test,github.com" {
		t.Errorf("hosts = %s", got)
	}
	if err := m.Verify("echo hello\n"); err != nil {
		t.Fatal(err)
	}
	if err := m.Verify("echo changed\n"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("changed script verification = %v", err)
	}
	m.OS = "not-" + runtime.GOOS
	if err := m.Verify("echo hello\n"); err == nil || !strings.Contains(err.Error(), "OS mismatch") {
		t.Errorf("different OS verification = %v", err)
	}
}

func TestManifestRoundTripAndApply(t *testing.T) {
	m := New("x.sh", "df\n")
	m.Commands = []string{"df"}
	m.Hosts = []string{"downloads.example.test"}
	path := t.TempDir() + "/manifest.yaml"
	if err := m.Write(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.OS != runtime.GOOS {
		t.Errorf("round-trip OS = %q, want %q", got.OS, runtime.GOOS)
	}
	cfg := sandbox.Config{Allowed: command.NewSet("uname"), Network: sandbox.DefaultPolicy()}
	got.Apply(&cfg)
	if !cfg.Strict || !cfg.Allowed["df"] || cfg.Allowed["uname"] {
		t.Errorf("manifest command policy = strict %v, allowed %v", cfg.Strict, cfg.Allowed)
	}
	if !cfg.Network.AllowsTarget("https://downloads.example.test/tool") || cfg.Network.AllowsTarget("https://other.test/tool") {
		t.Errorf("manifest host policy did not apply")
	}
}

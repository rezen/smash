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
		// What the in-process downloader observed: the redirect hops and the
		// response's declared media type. An api.github.com hop scopes to its
		// owner/repo; an opaque asset host stays host-level.
		Via: []string{
			"https://downloads.example.test/tool",
			"https://api.github.com/repos/gruntwork-io/terragrunt/releases/latest",
			"https://objects.example.test/bucket/uuid",
		},
		ContentType: "application/gzip",
		Sniffed:     "application/x-gzip",
	})
	p.Audit(sandbox.AuditRecord{Name: "uname"})
	p.Audit(sandbox.AuditRecord{ // a project-shaped fetch scopes to owner/repo
		Name: "curl",
		Resources: []command.Resource{
			{Kind: "url", Action: "fetch", Value: "https://github.com/atuinsh/atuin/releases/latest/download/x"},
		},
	})
	p.Audit(sandbox.AuditRecord{ // too short to name a project → host fallback
		Name: "curl",
		Resources: []command.Resource{
			{Kind: "url", Action: "fetch", Value: "https://github.com/atuinsh"},
		},
	})
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
	if got := strings.Join(m.URLs, ","); got != "https://api.github.com/repos/gruntwork-io/terragrunt,https://github.com/atuinsh/atuin" {
		t.Errorf("urls = %s (project-shaped URLs must scope to owner/repo)", got)
	}
	if got := strings.Join(m.Hosts, ","); got != "downloads.example.test,github.com,objects.example.test" {
		t.Errorf("hosts = %s (non-project URLs, hops and git remotes stay host-level)", got)
	}
	if got := strings.Join(m.MIMETypes, ","); got != "application/gzip" {
		t.Errorf("mime-types = %s (the declared type, never the sniffed one)", got)
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
	m.URLs = []string{"https://github.com/o/r"}
	m.Hosts = []string{"downloads.example.test"}
	m.MIMETypes = []string{"application/gzip", "text/*"}
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
	// The urls entry is a whole-segment, scheme-pinned prefix grant: one
	// project, not the forge.
	if !cfg.Network.AllowsTarget("https://github.com/o/r/releases/download/v1/x") {
		t.Errorf("the recorded project prefix must admit its release downloads")
	}
	for _, target := range []string{
		"https://github.com/o/other/releases/download/v1/x",
		"https://github.com/other/r/x",
		"http://github.com/o/r/x", // prefix grants pin the scheme
	} {
		if cfg.Network.AllowsTarget(target) {
			t.Errorf("%s should not be admitted by the o/r prefix", target)
		}
	}
	if !cfg.Network.AllowsMIME("application/gzip") || !cfg.Network.AllowsMIME("text/x-shellscript") ||
		cfg.Network.AllowsMIME("application/octet-stream") {
		t.Errorf("manifest mime-types did not apply: %v", cfg.Network.AllowedMIMETypes)
	}
}

// TestManifestURLsValidated: like a schemeless policy prefix, a malformed
// urls entry would fail closed silently at enforce time; Load refuses it.
func TestManifestURLsValidated(t *testing.T) {
	m := New("x.sh", "df\n")
	m.URLs = []string{"github.com/o/r"}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "urls") {
		t.Errorf("a schemeless urls entry should be refused; got %v", err)
	}
}

// TestProfilerOmitsMIMETypesAfterUntypedBody: enforcement denies a missing
// Content-Type whenever a mime-types list is set, so one observed untyped
// body poisons the whole list — writing it would break replaying the very
// script that was profiled.
func TestProfilerOmitsMIMETypesAfterUntypedBody(t *testing.T) {
	p := NewProfiler("install.sh", "echo hello\n", nil)
	p.Audit(sandbox.AuditRecord{Name: "curl", ContentType: "application/gzip", Sniffed: "application/x-gzip"})
	p.Audit(sandbox.AuditRecord{Name: "curl", ContentType: "", Sniffed: "text/plain"})
	if m := p.Manifest(); m.MIMETypes != nil {
		t.Errorf("mime-types = %v, want omitted after an untyped response body", m.MIMETypes)
	}
}

// TestManifestMIMETypes: the field is optional — absent leaves whatever the
// policy set — and a malformed entry is refused at load time.
func TestManifestMIMETypes(t *testing.T) {
	m := New("x.sh", "df\n")
	cfg := sandbox.Config{Network: sandbox.DefaultPolicy()}
	cfg.Network.AllowedMIMETypes = []string{"text/*"}
	m.Apply(&cfg)
	if got := strings.Join(cfg.Network.AllowedMIMETypes, ","); got != "text/*" {
		t.Errorf("a manifest without mime-types must leave the policy's list; got %q", got)
	}

	m.MIMETypes = []string{"*/*"}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "*/*") {
		t.Errorf("Validate should refuse and name a malformed entry; got %v", err)
	}
}

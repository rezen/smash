package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

// hostPath is a PATH of real host bin dirs, so allow-listed commands resolve.
const hostPath = "PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"

// fixture reads a vendored installer from the repo's fixtures directory.
func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

type option = func(*Config)

// withHome gives the script scoped HOME and TMPDIR paths under the sandbox root
// plus the host PATH — the shape real installers expect. Extra env entries are
// appended and can override any of those defaults.
func withHome(t *testing.T, extra ...string) option {
	t.Helper()
	return func(cfg *Config) {
		home := filepath.Join(cfg.Root, "home")
		tmp := filepath.Join(cfg.Root, "tmp")
		if err := os.MkdirAll(home, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			t.Fatal(err)
		}
		cfg.Dir = home
		cfg.Env = expand.ListEnviron(append([]string{"HOME=" + home, "TMPDIR=" + tmp, hostPath, "TERM=dumb"}, extra...)...)
	}
}

// lockedBuffer is a bytes.Buffer safe for concurrent writers: the members of a
// shell pipeline are real processes whose stdout/stderr are copied in from
// separate goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runConfined runs script through the full sandbox in a fresh temp root with
// the default policy and allow-list, returning captured stdout and stderr.
func runConfined(t *testing.T, script string, opts ...option) (stdout, stderr string, err error) {
	t.Helper()
	root := t.TempDir()
	var out, er lockedBuffer
	cfg := NewConfig(root, root, expand.ListEnviron("PATH=/usr/bin:/bin"))
	// Offline by default. The default policy allows the GitHub release hosts,
	// which several fixtures really do fetch from, so a test that wants the
	// network has to say so — otherwise the suite would depend on it.
	cfg.Network.AllowedPrefixes = nil
	cfg.Stdout, cfg.Stderr = &out, &er
	for _, o := range opts {
		o(&cfg)
	}
	err = Run(cfg, "test", script)
	return out.String(), er.String(), err
}

// tarballBytes builds a gzip tarball of executable files (name → body) in memory.
func tarballBytes(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeBinary is the body of a stand-in executable that echoes its name and args.
func fakeBinary(name string) string { return "#!/bin/sh\necho fake " + name + " $*\n" }

// auditInto returns an Auditor that appends every record to *recs. Audit is
// called concurrently — pipeline stages and backgrounded commands (`cmd &`)
// each record themselves from their own goroutine — so the append is locked.
// Every test that collects records goes through this.
func auditInto(recs *[]AuditRecord) Auditor {
	var mu sync.Mutex
	return AuditorFunc(func(r AuditRecord) {
		mu.Lock()
		defer mu.Unlock()
		*recs = append(*recs, r)
	})
}

// collectAudit wires auditInto into cfg, with stream capture on.
func collectAudit(recs *[]AuditRecord) option {
	return func(c *Config) {
		c.AuditData = 256
		c.Auditor = auditInto(recs)
	}
}

// auditFileChanges flattens the audit trail into "op basename" entries — the
// file-change list a monitor would consume.
func auditFileChanges(recs []AuditRecord) []string {
	var changes []string
	for _, r := range recs {
		for _, c := range r.Files {
			changes = append(changes, string(c.Op)+" "+filepath.Base(c.Path))
		}
	}
	return changes
}

// assertChanges checks that each wanted "op basename" entry appears in the
// audit trail's file changes.
func assertChanges(t *testing.T, recs []AuditRecord, wants ...string) {
	t.Helper()
	changes := auditFileChanges(recs)
	joined := strings.Join(changes, ",")
	for _, want := range wants {
		if !strings.Contains(joined, want) {
			t.Errorf("audit file changes missing %q; got %v", want, changes)
		}
	}
}

// assertConfined fails if any audited file change landed outside root.
// Tolerated: /dev/null sinks, the mktemp describer's unexpanded "$TMPDIR/…"
// template, and relative paths — the audit records them as the command saw
// them, relative to a cwd that is itself inside the root or its scratch tree.
func assertConfined(t *testing.T, recs []AuditRecord, root string) {
	t.Helper()
	sep := string(filepath.Separator)
	for _, r := range recs {
		for _, c := range r.Files {
			if !filepath.IsAbs(c.Path) || strings.HasPrefix(c.Path, root+sep) ||
				strings.HasPrefix(c.Path, "/dev/") || strings.HasPrefix(c.Path, "$") {
				continue
			}
			t.Errorf("%s changed a path outside the sandbox root: %s", r.Name, c.Path)
		}
	}
}

// runInstalled runs a command line against an already-populated sandbox (the
// same cfg an installer just ran under) and returns its stdout.
func runInstalled(t *testing.T, cfg Config, script string) string {
	t.Helper()
	var out, er lockedBuffer
	cfg.Stdout, cfg.Stderr = &out, &er
	if err := Run(cfg, "verify", script); err != nil {
		t.Fatalf("%q failed: %v\nstderr=%s", script, err, er.String())
	}
	return out.String()
}

// envWith returns env with the given NAME=value entries overriding any
// existing ones.
func envWith(env expand.Environ, entries ...string) expand.Environ {
	over := map[string]string{}
	for _, e := range entries {
		name, val, _ := strings.Cut(e, "=")
		over[name] = val
	}
	var list []string
	env.Each(func(name string, vr expand.Variable) bool {
		if _, ok := over[name]; !ok {
			list = append(list, name+"="+vr.String())
		}
		return true
	})
	return expand.ListEnviron(append(list, entries...)...)
}

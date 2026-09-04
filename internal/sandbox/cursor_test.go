package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestCursorInstallerAuditTrail runs Cursor's agent installer (fixtures/cursor.sh)
// with NO network. Its one download is streamed — `curl … | tar -xzf -` — so the
// mock answers on stdout with a real tarball and tar extracts it from the pipe.
// The versioned install and both symlinks land under the sandbox HOME, and the
// linked "binary" then runs from inside the root.
func TestCursorInstallerAuditTrail(t *testing.T) {
	var recs []AuditRecord
	var download *Mock
	var cfg Config
	out, er, err := runConfined(t, fixture(t, "cursor.sh"), withHome(t, "SHELL=/bin/zsh"), collectAudit(&recs), func(c *Config) {
		// Real packages wrap everything in one top-level dir; the installer
		// strips it with --strip-components=1.
		pkg := tarballBytes(t, map[string]string{"package/cursor-agent": fakeBinary("cursor-agent")})
		download = c.Mock(MatchName("curl").And(MatchResource("url", "https://downloads.cursor.com/lab/*/agent-cli-package.tar.gz")),
			string(pkg), "", 0)
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	if !strings.Contains(out, "Installation Complete!") {
		t.Errorf("unexpected output:\n%s\n%s", out, er)
	}
	if download.Called() != 1 {
		t.Fatalf("download curl called %d times", download.Called())
	}
	if dl := download.Calls()[0].TypedParams().(command.CurlParams); !dl.Follow || !dl.FailFast || dl.Output != "" {
		t.Errorf("download curl params (expected -fSL streamed to stdout): %+v", dl)
	}

	// Extract into the temp version dir, atomic move into place, then the
	// two symlinks — all inside the root.
	assertChanges(t, recs, "extract", "move", "link agent", "link cursor-agent")
	assertConfined(t, recs, cfg.Root)

	bin := filepath.Join(cfg.Dir, ".local", "bin")
	for _, link := range []string{"agent", "cursor-agent"} {
		target, err := os.Readlink(filepath.Join(bin, link))
		if err != nil {
			t.Fatalf("%s symlink: %v", link, err)
		}
		if !strings.HasPrefix(target, cfg.Dir) || filepath.Base(target) != "cursor-agent" {
			t.Errorf("%s → %s, want a cursor-agent inside the sandbox HOME", link, target)
		}
	}
	if got := runInstalled(t, cfg, filepath.Join(bin, "agent")+" --version"); !strings.Contains(got, "fake cursor-agent --version") {
		t.Errorf("installed agent output: %q", got)
	}
}

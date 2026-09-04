package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestWarpInstallerAuditTrail runs Warp's agent CLI installer (fixtures/warp.sh)
// with NO network. Its version probe is `curl -o /dev/null -w '%{redirect_url}'`
// — the mock answers the pinned artifact URL, which names the version — and the
// download writes a real tarball with the renamed binary plus its resources/
// tree. The install exercises the versioned layout end to end: staging via
// `mktemp -d` inside the root, the noclobber install lock, the atomic `current`
// swap (`command -p mv -fh` on macOS), and the PATH symlink. Running the
// installer a second time on the same root reuses the completed version.
func TestWarpInstallerAuditTrail(t *testing.T) {
	const artifact = "https://app.warp.dev/download/stable/1.2.3/tui/macos/aarch64/warp-tui.tar.gz"
	var recs []AuditRecord
	var probe, download *Mock
	var cfg Config
	out, er, err := runConfined(t, fixture(t, "warp.sh"), withHome(t, "SHELL=/bin/zsh"), collectAudit(&recs), func(c *Config) {
		probe = c.Mock(MatchName("curl").And(MatchResource("url", "https://app.warp.dev/download/agent-cli/artifact?os=*&arch=*")),
			artifact, "", 0)
		download = c.MockFunc(MatchName("curl").And(MatchResource("url", artifact)),
			func(p command.ParsedCommand) (string, string, int) {
				cp := p.TypedParams().(command.CurlParams)
				tb := tarballBytes(t, map[string]string{
					"warp-tui-stable":   fakeBinary("warp"),
					"resources/version": "1.2.3\n",
				})
				if err := os.WriteFile(cp.Output, tb, 0o644); err != nil {
					t.Fatal(err)
				}
				return "", "", 0
			})
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	install := filepath.Join(cfg.Dir, ".warp", "tui")
	if !strings.Contains(out, "Warp Agent CLI 1.2.3 installed to "+filepath.Join(install, "versions", "1.2.3")) {
		t.Errorf("unexpected output:\n%s\n%s", out, er)
	}
	if probe.Called() != 1 || download.Called() != 1 {
		t.Fatalf("curl mocks: probe=%d download=%d", probe.Called(), download.Called())
	}
	if pr := probe.Calls()[0].TypedParams().(command.CurlParams); pr.Follow || pr.Output != "/dev/null" || pr.WriteOut != "%{redirect_url}" {
		t.Errorf("probe curl params (expected an unfollowed redirect probe): %+v", pr)
	}
	if dl := download.Calls()[0].TypedParams().(command.CurlParams); !dl.Follow || !dl.FailFast || dl.Output == "" {
		t.Errorf("download curl params: %+v", dl)
	}

	// Download, extract, payload moved into versions/1.2.3, `current` swapped
	// in, the lock released, the PATH symlink created; all inside the root.
	assertChanges(t, recs, "write warp-tui.tar.gz", "extract payload", "mode warp-tui-stable", "move 1.2.3",
		"link .current.new", "move current", "delete .update.lock", "link warp")
	assertConfined(t, recs, cfg.Root)

	// The versioned layout the header comment promises.
	if target, err := os.Readlink(filepath.Join(install, "current")); err != nil || target != "versions/1.2.3" {
		t.Errorf("current → %q (%v), want versions/1.2.3", target, err)
	}
	warp := filepath.Join(cfg.Dir, ".local", "bin", "warp")
	if target, err := os.Readlink(warp); err != nil || target != filepath.Join(install, "current", "warp-tui-stable") {
		t.Errorf("warp → %q (%v)", target, err)
	}
	if _, err := os.Stat(filepath.Join(install, "versions", "1.2.3", "resources", "version")); err != nil {
		t.Errorf("resources/ not installed alongside the binary: %v", err)
	}
	// The install lock was released and the staging dir cleaned up.
	if _, err := os.Stat(filepath.Join(install, ".update.lock")); err == nil {
		t.Error("install lock left behind")
	}
	if stale, _ := filepath.Glob(filepath.Join(install, "versions", ".warp-tui-install.*")); len(stale) > 0 {
		t.Errorf("staging dirs left behind: %v", stale)
	}
	if got := runInstalled(t, cfg, warp+" --version"); !strings.Contains(got, "fake warp --version") {
		t.Errorf("installed warp output: %q", got)
	}

	// Second run, same root: the completed version is immutable and reused,
	// the lock is taken and released again, nothing is re-downloaded.
	var out2, er2 lockedBuffer
	cfg.Stdout, cfg.Stderr = &out2, &er2
	if err := Run(cfg, "again", fixture(t, "warp.sh")); err != nil {
		t.Fatalf("second install failed: %v\nstdout=%s\nstderr=%s", err, out2.String(), er2.String())
	}
	if !strings.Contains(out2.String(), "Reusing existing Warp Agent CLI 1.2.3") {
		t.Errorf("second run output:\n%s", out2.String())
	}
	if download.Called() != 2 {
		t.Errorf("download curl called %d times over two runs, want 2", download.Called())
	}
}

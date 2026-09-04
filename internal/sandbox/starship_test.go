package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestStarshipInstallerAuditTrail runs Starship's installer (fixtures/starship.sh)
// with NO network. It is a POSIX-sh script with the opposite guard from nvm's:
// it refuses to run under bash unless POSIXLY_CORRECT is set. Its `#!/usr/bin/env
// sh` shebang puts the sandbox in POSIX mode, which advertises that variable
// alongside BASH_VERSION exactly as `curl … | sh` does, so the guard passes and
// the run completes: the release tarball download is mocked, `tar -xzof`
// unpacks it into the requested bin dir under the sandbox HOME, and the binary
// then runs from inside the root. The `tput` colour probes are not allow-listed
// and the script tolerates that (`|| printf ”`); `getconf LONG_BIT` is
// allow-listed but mocked so the arch detection is host-independent.
func TestStarshipInstallerAuditTrail(t *testing.T) {
	src := fixture(t, "starship.sh")

	var recs []AuditRecord
	var download *Mock
	var cfg Config
	out, er, err := runConfined(t, src, withHome(t), collectAudit(&recs), func(c *Config) {
		bin := filepath.Join(c.Dir, "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		c.Args = []string{"--yes", "--bin-dir", bin}
		c.Mock(MatchName("getconf"), "64\n", "", 0)
		download = c.MockFunc(MatchName("curl").And(MatchResource("url", "https://github.com/starship/starship/releases/latest/download/starship-*.tar.gz")),
			func(p command.ParsedCommand) (string, string, int) {
				cp := p.TypedParams().(command.CurlParams)
				if err := os.WriteFile(cp.Output, tarballBytes(t, map[string]string{"starship": fakeBinary("starship")}), 0o644); err != nil {
					t.Fatal(err)
				}
				return "", "", 0
			})
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	bin := filepath.Join(cfg.Dir, "bin")
	for _, want := range []string{
		"Bin directory " + bin + " is not in your $PATH",
		"Installing Starship, please wait",
		"Starship latest installed",
		"Please follow the steps for your shell",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s\n%s", want, out, er)
		}
	}
	if strings.Contains(out+er, "Escalated permissions") {
		t.Errorf("a writable bin dir must not escalate:\n%s\n%s", out, er)
	}
	if download.Called() != 1 {
		t.Fatalf("download curl called %d times", download.Called())
	}
	if dl := download.Calls()[0].TypedParams().(command.CurlParams); !dl.Follow || !dl.FailFast || !dl.Silent || dl.Output == "" {
		t.Errorf("download curl params: %+v", dl)
	}
	// Writable probe on the bin dir, the download, the extraction into bin.
	assertChanges(t, recs, "touch test.txt", "delete test.txt", "extract bin")
	assertConfined(t, recs, cfg.Root)

	if got := runInstalled(t, cfg, filepath.Join(bin, "starship")+" --version"); !strings.Contains(got, "fake starship --version") {
		t.Errorf("installed starship output: %q", got)
	}
}

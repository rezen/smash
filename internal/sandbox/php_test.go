package sandbox

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestPHPInstallerAuditTrail runs php.new's Herd Lite installer (fixtures/php.sh)
// with NO network. It backgrounds each `curl -L … -o FILE` and `wait`s on it, so
// the four downloads are mocked to write fake binaries. The install (binaries,
// php.ini, uninstall script) lands under the sandbox HOME, the shell profile
// gets the PATH export, and the downloaded "php" then runs from inside the root
// when the script probes its version.
func TestPHPInstallerAuditTrail(t *testing.T) {
	var recs []AuditRecord
	var download *Mock
	var cfg Config
	out, er, err := runConfined(t, fixture(t, "php.sh"), withHome(t, "SHELL=/bin/zsh"), collectAudit(&recs), func(c *Config) {
		if err := os.WriteFile(filepath.Join(c.Dir, ".zshrc"), []byte("# rc\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		download = c.MockFunc(MatchName("curl"), func(p command.ParsedCommand) (string, string, int) {
			cp := p.TypedParams().(command.CurlParams)
			body := "fake " + path.Base(cp.URL) + "\n"
			if path.Base(cp.URL) == "php" {
				body = "#!/bin/sh\necho 'PHP 8.5.0 (cli) fake'\n"
			}
			if err := os.WriteFile(cp.Output, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			return "", "", 0
		})
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	if !strings.Contains(out, "have been installed successfully") {
		t.Errorf("unexpected output:\n%s\n%s", out, er)
	}

	// Four downloads, each followed (-L) into its own file; the PHP build is
	// chosen by the host arch, the rest are fixed URLs.
	var urls []string
	for _, p := range download.Calls() {
		cp := p.TypedParams().(command.CurlParams)
		if !cp.Follow || cp.Output == "" {
			t.Errorf("download curl params: %+v", cp)
		}
		urls = append(urls, cp.URL)
	}
	sort.Strings(urls)
	want := []string{
		"https://curl.se/ca/cacert.pem",
		"https://download.herdphp.com/herd-lite/composer",
		"https://download.herdphp.com/herd-lite/macos/*/8.5/php",
		"https://download.herdphp.com/resources/laravel",
	}
	if len(urls) != len(want) {
		t.Fatalf("fetched %d URLs, want %d: %v", len(urls), len(want), urls)
	}
	for i := range want {
		if !globRE(want[i]).MatchString(urls[i]) {
			t.Errorf("fetched %q, want %q", urls[i], want[i])
		}
	}

	installDir := filepath.Join(cfg.Dir, ".config", "herd-lite", "bin")
	for _, name := range []string{"php", "composer", "laravel", "uninstall_herd_lite"} {
		fi, err := os.Stat(filepath.Join(installDir, name))
		if err != nil {
			t.Errorf("%s: %v", name, err)
		} else if fi.Mode()&0o100 == 0 {
			t.Errorf("%s is not executable: %v", name, fi.Mode())
		}
	}
	ini, _ := os.ReadFile(filepath.Join(installDir, "php.ini"))
	if !strings.Contains(string(ini), "curl.cainfo="+filepath.Join(installDir, "cacert.pem")) || !strings.Contains(string(ini), "pcre.jit=0") {
		t.Errorf("php.ini:\n%s", ini)
	}
	rc, _ := os.ReadFile(filepath.Join(cfg.Dir, ".zshrc"))
	if !strings.Contains(string(rc), `export PATH="`+installDir+`:$PATH"`) || !strings.Contains(string(rc), "PHP_INI_SCAN_DIR") {
		t.Errorf(".zshrc was not updated:\n%s", rc)
	}

	// Every download is a write, the binaries are chmod'ed, and the profile
	// edit is recorded — nothing outside the root.
	assertChanges(t, recs, "write php", "write composer", "write laravel", "write cacert.pem", "mode php", "mode uninstall_herd_lite")
	assertConfined(t, recs, cfg.Root)
	if got := runInstalled(t, cfg, filepath.Join(installDir, "php")+" -v"); !strings.Contains(got, "PHP 8.5.0 (cli) fake") {
		t.Errorf("installed php output: %q", got)
	}
}

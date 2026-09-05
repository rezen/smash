package sandbox

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"

	"github.com/rezen/smash/internal/command"
)

// TestUVInstallerAuditTrail runs uv's installer (fixtures/uv-installer.sh) with
// NO network: the release download is mocked to write a real tarball holding
// fake `uv`/`uvx` scripts, and sha256sum is mocked to answer the checksum the
// installer expects for that artifact. The install lands under the sandbox
// HOME, the installed "binary" then runs from inside the root, and the same
// binary's network subcommand is stopped by the egress guard.
func TestUVInstallerAuditTrail(t *testing.T) {
	src := fixture(t, "uv-installer.sh")
	var recs []AuditRecord
	var download, checksum *Mock
	var cfg Config
	var out, er bytes.Buffer
	var artifact string
	_, _, err := runConfined(t, src, withHome(t), func(c *Config) {
		installDir := filepath.Join(c.Dir, ".local", "bin")
		tmp := filepath.Join(c.Root, "tmp")
		if err := os.MkdirAll(tmp, 0o755); err != nil {
			t.Fatal(err)
		}
		c.Env = expand.ListEnviron(
			"HOME="+c.Dir,
			"TMPDIR="+tmp, // mktemp lands inside the root too
			// /sbin so `command -v sha256sum` is honest on macOS and the checksum path runs
			"PATH="+installDir+":/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin:/usr/sbin:/sbin",
			"UV_INSTALL_DIR="+installDir,
			"UV_NO_MODIFY_PATH=1", // don't rewrite shell profiles
			"TERM=dumb",
		)
		c.Stdout, c.Stderr = &out, &er
		c.AuditData = 256
		c.Auditor = auditInto(&recs)
		download = c.MockFunc(MatchName("curl").And(MatchResource("url", "https://releases.astral.sh/*")),
			func(p command.ParsedCommand) (string, string, int) {
				cp := p.TypedParams().(command.CurlParams)
				artifact = path.Base(cp.URL)
				// Real release tarballs wrap the bins in one top-level dir; the
				// installer extracts with --strip-components 1.
				dir := strings.TrimSuffix(artifact, ".tar.gz")
				writeFakeTarball(t, cp.Output, map[string]string{
					dir + "/uv":  "#!/bin/sh\necho fake uv $*\n",
					dir + "/uvx": "#!/bin/sh\necho fake uvx $*\n",
				})
				return "", "", 0
			})
		checksum = c.MockFunc(MatchName("sha256sum"), func(p command.ParsedCommand) (string, string, int) {
			return uvChecksumFor(t, src, artifact) + " *" + p.Argv()[len(p.Argv())-1] + "\n", "", 0
		})
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out.String(), er.String())
	}
	if !strings.Contains(out.String(), "everything's installed!") {
		t.Errorf("unexpected output:\n%s\n%s", out.String(), er.String())
	}
	if download.Called() != 1 {
		t.Errorf("download curl called %d times", download.Called())
	}
	if !strings.HasPrefix(artifact, "uv-") || !strings.HasSuffix(artifact, ".tar.gz") {
		t.Errorf("unexpected artifact %q", artifact)
	}
	if checksum.Called() != 1 {
		t.Errorf("sha256sum called %d times (checksum verification skipped or repeated)", checksum.Called())
	}
	if dl := download.Calls()[0].TypedParams().(command.CurlParams); !dl.Follow || !dl.FailFast || dl.Output == "" {
		t.Errorf("download curl params: %+v", dl)
	}

	// The audit trail as file changes: download, extract (old-style `tar xf`),
	// then each bin moved into place and made executable.
	var changes []string
	for _, r := range recs {
		for _, c := range r.Files {
			changes = append(changes, string(c.Op)+" "+filepath.Base(c.Path))
		}
	}
	joined := strings.Join(changes, ",")
	for _, want := range []string{"write input.tar.gz", "extract tmp", "mode uv", "mode uvx", "move bin"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit file changes missing %q; got %v", want, changes)
		}
	}
	// The in-process mktemp implementation keeps the installer's scratch tree
	// in the configured TMPDIR. The describer reports its unexpanded
	// "$TMPDIR/…" template rather than the generated path.
	for _, r := range recs {
		for _, c := range r.Files {
			inRoot := strings.HasPrefix(c.Path, cfg.Root+string(filepath.Separator))
			if !inRoot && !strings.HasPrefix(c.Path, "$") {
				t.Errorf("%s changed a path outside the sandbox root: %s", r.Name, c.Path)
			}
		}
	}

	// The installed binary is inside the root, so the allow-list's escape hatch
	// lets it run (resolved via the sandbox PATH, never the host's).
	installed := filepath.Join(cfg.Dir, ".local", "bin", "uv")
	if _, err := os.Stat(installed); err != nil {
		t.Fatalf("uv not installed at %s: %v", installed, err)
	}
	out.Reset()
	er.Reset()
	if err := Run(cfg, "verify", "uv --version"); err != nil {
		t.Fatalf("installed uv failed to run: %v\nstderr=%s", err, er.String())
	}
	if !strings.Contains(out.String(), "fake uv --version") {
		t.Errorf("installed uv output: %q", out.String())
	}

	// uv is a modelled package manager: its network subcommands are refused by
	// the egress guard even though the binary itself is allowed to run.
	out.Reset()
	er.Reset()
	if err := Run(cfg, "uv-egress", "uv python list"); err == nil {
		t.Errorf("uv python list reached the binary; stdout=%q", out.String())
	} else if !strings.Contains(er.String(), "[sandbox]") {
		t.Errorf("uv python list failed for another reason: %v\nstderr=%s", err, er.String())
	}
}

// uvChecksumFor pulls the sha256 the installer expects for artifact out of its
// own `case` table, so the mocked sha256sum can agree with it on any host arch.
func uvChecksumFor(t *testing.T, src, artifact string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)"` + regexp.QuoteMeta(artifact) + `"\)\s*.*?_checksum_value="([0-9a-f]{64})"`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("no checksum for %q in installer", artifact)
	}
	return m[1]
}

// writeFakeTarball writes a gzip tarball of executable files (name → body) to path.
func writeFakeTarball(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
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
}

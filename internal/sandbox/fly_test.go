package sandbox

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestFlyInstallerAuditTrail runs Fly.io's installer (fixtures/fly.sh) with
// NO network: both curls are mocked — the release lookup answers a URL, the
// download writes a real tarball holding a fake flyctl — and the installed
// "binary" then runs from inside the sandbox root. The audit trail shows the
// whole install as file changes, and the mocks show exactly what was fetched.
func TestFlyInstallerAuditTrail(t *testing.T) {
	var recs []AuditRecord
	var lookup, download *Mock
	var root string
	out, er, err := runConfined(t, fixture(t, "fly.sh"), withHome(t), func(c *Config) {
		root = c.Root
		c.Args = []string{"--non-interactive"}
		c.AuditData = 256
		c.Auditor = auditInto(&recs)
		lookup = c.Mock(MatchName("curl").And(MatchResource("url", "https://api.fly.io/app/flyctl_releases/*")),
			"https://github.com/superfly/flyctl/releases/download/v0.0.1/flyctl_test.tar.gz", "", 0)
		download = c.MockFunc(MatchName("curl").And(MatchResource("url", "https://github.com/superfly/*")),
			func(p command.ParsedCommand) (string, string, int) {
				cp := p.TypedParams().(command.CurlParams)
				writeFakeFlyctlTarball(t, cp.Output)
				return "200 " + cp.URL, "", 0
			})
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	if !strings.Contains(out, "flyctl was installed successfully") || !strings.Contains(out, "fake flyctl version -s shell") {
		t.Errorf("unexpected output:\n%s", out)
	}
	if lookup.Called() != 1 || download.Called() != 1 {
		t.Errorf("curl mocks: lookup=%d download=%d", lookup.Called(), download.Called())
	}
	if dl := download.Calls()[0].TypedParams().(command.CurlParams); !dl.Follow || !dl.FailFast || dl.WriteOut == "" {
		t.Errorf("download curl params: %+v", dl)
	}

	// The audit trail, as a monitor would consume it: one file-change list.
	var changes []string
	for _, r := range recs {
		for _, c := range r.Files {
			changes = append(changes, string(c.Op)+" "+filepath.Base(c.Path))
		}
	}
	for _, want := range []string{"create bin", "create tmp", "write flyctl.tar.gz", "extract tmp", "mode flyctl", "move flyctl", "delete flyctl.tar.gz", "link fly"} {
		if !strings.Contains(strings.Join(changes, ","), want) {
			t.Errorf("audit file changes missing %q; got %v", want, changes)
		}
	}
	// Nothing escaped the sandbox root: every changed path is under it.
	for _, r := range recs {
		for _, c := range r.Files {
			if !strings.HasPrefix(c.Path, root+string(filepath.Separator)) {
				t.Errorf("%s changed a path outside the sandbox root: %s", r.Name, c.Path)
			}
		}
	}
}

// writeFakeFlyctlTarball writes a gzip tarball containing an executable
// `flyctl` shell script to path.
func writeFakeFlyctlTarball(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	body := "#!/bin/sh\necho fake flyctl $*\n"
	if err := tw.WriteHeader(&tar.Header{Name: "flyctl", Mode: 0o755, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

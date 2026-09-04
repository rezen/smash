package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// Three vendored installers share the godownloader/shlib skeleton: resolve the
// release tag from GitHub (a JSON page fetched with an Accept header), download
// a tarball plus a checksums file, verify the sha256, untar, `install` the
// binary into BINDIR. They differ only in project names and download hosts:
//
//	fixtures/bearer.sh   — Bearer/bearer, everything from github.com
//	fixtures/truffle.sh  — trufflesecurity/trufflehog, checksums fetched first
//	fixtures/aqua.sh     — aquasecurity/trivy, tarball from get.trivy.dev
//
// Every test runs under Linux/x86_64 emulation so the artifact names are
// host-independent (the scripts derive them from `uname`).
var godownloaderInstallers = []struct {
	name, fixture, binary, tarball, lookupURL, tarballURL, checksumURL string
}{
	{
		name: "bearer", fixture: "bearer.sh", binary: "bearer",
		tarball:     "bearer_1.2.3_linux_amd64.tar.gz",
		lookupURL:   "https://github.com/Bearer/bearer/releases/latest",
		tarballURL:  "https://github.com/Bearer/bearer/releases/download/v1.2.3/bearer_1.2.3_linux_amd64.tar.gz",
		checksumURL: "https://github.com/Bearer/bearer/releases/download/v1.2.3/checksums.txt",
	},
	{
		name: "trufflehog", fixture: "truffle.sh", binary: "trufflehog",
		tarball:     "trufflehog_1.2.3_linux_amd64.tar.gz",
		lookupURL:   "https://github.com/trufflesecurity/trufflehog/releases/latest",
		tarballURL:  "https://github.com/trufflesecurity/trufflehog/releases/download/v1.2.3/trufflehog_1.2.3_linux_amd64.tar.gz",
		checksumURL: "https://github.com/trufflesecurity/trufflehog/releases/download/v1.2.3/trufflehog_1.2.3_checksums.txt",
	},
	{
		name: "trivy", fixture: "aqua.sh", binary: "trivy",
		tarball:     "trivy_1.2.3_Linux-64bit.tar.gz",
		lookupURL:   "https://github.com/aquasecurity/trivy/releases/latest",
		tarballURL:  "https://get.trivy.dev/trivy?os=Linux&arch=64bit&version=1.2.3&type=tar.gz&client=install-script",
		checksumURL: "https://github.com/aquasecurity/trivy/releases/download/v1.2.3/trivy_1.2.3_checksums.txt",
	},
}

// godownloaderRelease is a fake release: the tarball bytes, their real sha256,
// and the mocks that serve them. checksum is what the checksums file advertises
// — normally the real hash, or a wrong one to simulate tampering.
type godownloaderRelease struct {
	tarball, binary string
	bytes           []byte
	hash, checksum  string
	curl, sha       *Mock
}

func newGodownloaderRelease(t *testing.T, tarball, binary string) *godownloaderRelease {
	t.Helper()
	b := tarballBytes(t, map[string]string{binary: fakeBinary(binary)})
	sum := sha256.Sum256(b)
	r := &godownloaderRelease{tarball: tarball, binary: binary, bytes: b, hash: hex.EncodeToString(sum[:])}
	r.checksum = r.hash
	return r
}

// mock registers the fake release on cfg: every curl is answered by URL (the
// tag lookup, the tarball, the checksums file) with the "200" the script reads
// back through -w '%{http_code}', and whichever sha256 tool the host offers
// (gsha256sum/sha256sum/shasum) reports the tarball's real hash. Both run
// before the allow-list, so no network is touched and no host tool runs.
func (r *godownloaderRelease) mock(t *testing.T) option {
	return func(c *Config) {
		c.Emulation = Emulation{UnameOS: "Linux", UnameArch: "x86_64"}
		r.curl = c.MockFunc(MatchName("curl"), func(p command.ParsedCommand) (string, string, int) {
			cp := p.TypedParams().(command.CurlParams)
			var body []byte
			switch {
			case strings.HasSuffix(cp.URL, "/releases/latest"):
				body = []byte(`{"id":1,"tag_name":"v1.2.3","name":"v1.2.3"}`)
			case strings.HasSuffix(path.Base(cp.URL), "checksums.txt"):
				body = []byte(r.checksum + "  " + r.tarball + "\n")
			default:
				body = r.bytes
			}
			if err := os.WriteFile(cp.Output, body, 0o644); err != nil {
				t.Fatal(err)
			}
			return "200", "", 0
		})
		r.sha = c.MockFunc(MatchName("gsha256sum", "sha256sum", "shasum"), func(p command.ParsedCommand) (string, string, int) {
			return r.hash + "  " + p.Argv()[len(p.Argv())-1] + "\n", "", 0
		})
	}
}

// fetched returns the URLs the curl mock answered, sorted.
func (r *godownloaderRelease) fetched() []string {
	var urls []string
	for _, p := range r.curl.Calls() {
		urls = append(urls, p.TypedParams().(command.CurlParams).URL)
	}
	sort.Strings(urls)
	return urls
}

// TestGodownloaderInstallersAuditTrail runs each installer with NO network:
// the three fetches are mocked, the checksum is verified against the fake
// tarball's real sha256, and the binary is `install`ed under the sandbox HOME
// — where the allow-list's escape hatch then lets it run.
func TestGodownloaderInstallersAuditTrail(t *testing.T) {
	for _, tc := range godownloaderInstallers {
		t.Run(tc.name, func(t *testing.T) {
			rel := newGodownloaderRelease(t, tc.tarball, tc.binary)
			var recs []AuditRecord
			var cfg Config
			out, er, err := runConfined(t, fixture(t, tc.fixture), withHome(t), rel.mock(t), collectAudit(&recs), func(c *Config) {
				c.Args = []string{"-b", filepath.Join(c.Dir, "bin")}
				cfg = *c
			})
			if err != nil {
				t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
			}
			installed := filepath.Join(cfg.Dir, "bin", tc.binary)
			if !strings.Contains(out, "found version: 1.2.3 for v1.2.3/") || !strings.Contains(out, "installed "+installed) {
				t.Errorf("unexpected output:\n%s\n%s", out, er)
			}

			// Exactly the three fetches, at the URLs the script builds from
			// the tag it was told; the tag lookup asks GitHub for JSON.
			want := []string{tc.lookupURL, tc.tarballURL, tc.checksumURL}
			sort.Strings(want)
			if got := rel.fetched(); strings.Join(got, "\n") != strings.Join(want, "\n") {
				t.Errorf("fetched URLs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			lookup := rel.curl.Calls()[0].TypedParams().(command.CurlParams)
			if lookup.URL != tc.lookupURL || !lookup.Follow || lookup.WriteOut != "%{http_code}" ||
				len(lookup.Headers) != 1 || lookup.Headers[0] != "Accept:application/json" {
				t.Errorf("tag lookup curl params: %+v", lookup)
			}
			if rel.sha.Called() != 1 {
				t.Errorf("sha256 tool called %d times (checksum verification skipped or repeated)", rel.sha.Called())
			}

			// The audit trail shows both downloads, the extraction (in the
			// scratch dir, so `tar` sees "."), and `install` writing into
			// bin/ — nothing outside the root but mktemp's scratch dir.
			assertChanges(t, recs, "write "+tc.tarball, "write "+path.Base(tc.checksumURL), "extract .", "write bin")
			assertConfined(t, recs, cfg.Root)

			if _, err := os.Stat(installed); err != nil {
				t.Fatalf("%s not installed: %v", tc.binary, err)
			}
			if got := runInstalled(t, cfg, installed+" --version"); !strings.Contains(got, "fake "+tc.binary+" --version") {
				t.Errorf("installed %s output: %q", tc.binary, got)
			}
		})
	}
}

// TestGodownloaderChecksumMismatchStopsInstall: the installers' own guard,
// exercised through the sandbox — when the advertised checksum doesn't match
// the downloaded tarball, the script refuses and installs nothing. The sha256
// mock reports the real hash, so only the checksums file is "tampered".
func TestGodownloaderChecksumMismatchStopsInstall(t *testing.T) {
	for _, tc := range godownloaderInstallers {
		t.Run(tc.name, func(t *testing.T) {
			rel := newGodownloaderRelease(t, tc.tarball, tc.binary)
			rel.checksum = strings.Repeat("0", 64)
			var home string
			out, er, err := runConfined(t, fixture(t, tc.fixture), withHome(t), rel.mock(t), func(c *Config) {
				c.Args = []string{"-b", filepath.Join(c.Dir, "bin")}
				home = c.Dir
			})
			if err == nil {
				t.Fatalf("expected the install to be refused; got success\n%s", out)
			}
			if !strings.Contains(er, "did not verify") {
				t.Errorf("expected a checksum failure; stderr:\n%s", er)
			}
			if _, statErr := os.Stat(filepath.Join(home, "bin", tc.binary)); statErr == nil {
				t.Errorf("%s was installed despite the checksum mismatch", tc.binary)
			}
		})
	}
}

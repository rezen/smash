package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// terragruntRelease is a fake v0.99.0 release under Linux/x86_64 emulation:
// the binary, its real sha256, and the mocks that serve the four fetches
// (release probe, binary, SHA256SUMS, GPG signature) plus the signing key.
// Everything runs before the allow-list and the network, so nothing leaves
// the process.
type terragruntRelease struct {
	binary, hash   string
	bytes          []byte
	curl, key, sha *Mock
}

const terragruntVersion = "v0.99.0" // signed (>= 0.98.0) but not attested (< 1.1.0): no gh involved

func newTerragruntRelease(t *testing.T) *terragruntRelease {
	t.Helper()
	b := []byte("#!/bin/sh\necho terragrunt version " + terragruntVersion + " fake $*\n")
	sum := sha256.Sum256(b)
	return &terragruntRelease{binary: "terragrunt_linux_amd64", bytes: b, hash: hex.EncodeToString(sum[:])}
}

func (r *terragruntRelease) mock(t *testing.T) option {
	return func(c *Config) {
		c.Emulation = Emulation{UnameOS: "Linux", UnameArch: "x86_64"}
		r.curl = c.MockFunc(MatchName("curl").And(MatchResource("url", "https://github.com/gruntwork-io/terragrunt/releases/*")), func(p command.ParsedCommand) (string, string, int) {
			cp := p.TypedParams().(command.CurlParams)
			if cp.Head { // latest-version probe: the script reads the Location header
				return "HTTP/2 302\r\nlocation: https://github.com/gruntwork-io/terragrunt/releases/tag/" + terragruntVersion + "\r\n\r\n", "", 0
			}
			var body []byte
			switch path.Base(cp.URL) {
			case "SHA256SUMS":
				body = []byte(r.hash + "  " + r.binary + "\n")
			case "SHA256SUMS.gpgsig":
				body = []byte("fake detached signature\n")
			default:
				body = r.bytes
			}
			if err := os.WriteFile(cp.Output, body, 0o644); err != nil {
				t.Fatal(err)
			}
			return "", "", 0
		})
		r.sha = c.MockFunc(MatchName("sha256sum", "shasum"), func(p command.ParsedCommand) (string, string, int) {
			return r.hash + "  " + p.Argv()[len(p.Argv())-1] + "\n", "", 0
		})
	}
}

// mockKey serves the Gruntwork signing key on stdout (the script pipes it
// into `gpg --import`).
func (r *terragruntRelease) mockKey() option {
	return func(c *Config) {
		r.key = c.Mock(MatchName("curl").And(MatchResource("url", "https://gruntwork.io/.well-known/pgp-key.txt")),
			"-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n", "", 0)
	}
}

// fetched returns the URLs the curl mocks answered, sorted.
func (r *terragruntRelease) fetched() []string {
	var urls []string
	for _, m := range []*Mock{r.curl, r.key} {
		if m == nil {
			continue
		}
		for _, p := range m.Calls() {
			urls = append(urls, p.TypedParams().(command.CurlParams).URL)
		}
	}
	sort.Strings(urls)
	return urls
}

// TestTerragruntInstallerAuditTrail runs Terragrunt's installer
// (fixtures/terragrunt.sh) with NO network and NO real gpg: a stand-in `gpg`
// inside the sandbox satisfies its `command -v gpg` dependency check on hosts
// without one, and a mock answers the two gpg calls (key import from the piped curl, then the
// detached-signature verify) so the default GPG verification path runs end to
// end. The latest version comes from the HEAD probe's Location header, the
// checksum is verified against the fake binary's real sha256, and the binary
// is `install`ed under the sandbox HOME — where it then runs, and where a
// second run of the installer finds it already installed.
func TestTerragruntInstallerAuditTrail(t *testing.T) {
	rel := newTerragruntRelease(t)
	var recs []AuditRecord
	var gpg *Mock
	var cfg Config
	out, er, err := runConfined(t, fixture(t, "terragrunt.sh"), collectAudit(&recs), rel.mock(t), rel.mockKey(), func(c *Config) {
		home := filepath.Join(c.Root, "home")
		fakeBin := filepath.Join(home, "fakebin")
		if err := os.MkdirAll(fakeBin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(fakeBin, "gpg"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		withHome(t, "SHELL=/bin/zsh")(c)
		c.Env = envWith(c.Env, "PATH="+fakeBin+":"+strings.TrimPrefix(hostPath, "PATH="))
		gpg = c.Mock(MatchName("gpg"), "", "", 0)
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	installDir := filepath.Join(cfg.Dir, ".terragrunt", "bin")
	for _, want := range []string{
		"Installing Terragrunt " + terragruntVersion + " for linux/amd64",
		"Skipping release attestation verification: not available for versions older than v1.1.0",
		"Signature verified",
		"SHA256 checksum verified",
		"Terragrunt " + terragruntVersion + " installed successfully to " + filepath.Join(installDir, "terragrunt"),
		"To add terragrunt to your PATH, run:",
	} {
		if !strings.Contains(out+er, want) {
			t.Errorf("output missing %q:\n%s\n%s", want, out, er)
		}
	}

	// The HEAD probe, three release assets, and the signing key.
	base := "https://github.com/gruntwork-io/terragrunt/releases/"
	want := []string{
		base + "latest",
		base + "download/" + terragruntVersion + "/" + rel.binary,
		base + "download/" + terragruntVersion + "/SHA256SUMS",
		base + "download/" + terragruntVersion + "/SHA256SUMS.gpgsig",
		"https://gruntwork.io/.well-known/pgp-key.txt",
	}
	sort.Strings(want)
	if got := rel.fetched(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("fetched URLs:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if probe := rel.curl.Calls()[0].TypedParams().(command.CurlParams); !probe.Head || !probe.FailFast || probe.URL != base+"latest" {
		t.Errorf("latest-version probe params: %+v", probe)
	}
	// gpg: import the key, then verify the detached signature over SHA256SUMS.
	if calls := gpg.Calls(); len(calls) != 2 || calls[0].Argv()[1] != "--import" || calls[1].Argv()[1] != "--verify" ||
		filepath.Base(calls[1].Argv()[2]) != "SHA256SUMS.gpgsig" || filepath.Base(calls[1].Argv()[3]) != "SHA256SUMS" {
		var argv []string
		for _, c := range calls {
			argv = append(argv, strings.Join(c.Argv(), " "))
		}
		t.Errorf("gpg calls: %v", argv)
	}
	if rel.sha.Called() != 1 {
		t.Errorf("sha256 tool called %d times", rel.sha.Called())
	}

	assertChanges(t, recs, "write "+rel.binary, "write SHA256SUMS", "write SHA256SUMS.gpgsig", "create gnupg", "mode gnupg", "create bin", "write terragrunt")
	assertConfined(t, recs, cfg.Root)

	installed := filepath.Join(installDir, "terragrunt")
	if fi, err := os.Stat(installed); err != nil || fi.Mode()&0o111 == 0 {
		t.Fatalf("terragrunt not installed executable: %v %v", fi, err)
	}
	if got := runInstalled(t, cfg, installed+" --version"); !strings.Contains(got, "terragrunt version "+terragruntVersion) {
		t.Errorf("installed terragrunt output: %q", got)
	}

	// Second run: the installer probes the installed binary's --version (the
	// fake, running from inside the root) and refuses to reinstall the same
	// version without --force.
	var out2, er2 lockedBuffer
	cfg.Stdout, cfg.Stderr = &out2, &er2
	if err := Run(cfg, "again", fixture(t, "terragrunt.sh")); err == nil {
		t.Errorf("second install should refuse without --force\n%s", out2.String())
	} else if !strings.Contains(er2.String(), "Terragrunt "+terragruntVersion+" is already installed at "+installed) {
		t.Errorf("second run stderr:\n%s", er2.String())
	}
}

// TestTerragruntKeyFetchOffAllowList is the run with only the release assets
// mocked, on a host that has gpg: gpg itself is allow-listed and runs for
// real, but the signing key comes from gruntwork.io, which is off the URL
// allow-list, so the in-process curl refuses the fetch, `gpg --import` gets
// nothing (pipefail), the installer's own guard aborts at "GPG signature
// verification failed", and nothing is installed. Passing --no-verify-sig is
// the installer's documented way past this — and with it the same run
// completes.
func TestTerragruntKeyFetchOffAllowList(t *testing.T) {
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed on host: the installer aborts at its dependency check instead")
	}
	rel := newTerragruntRelease(t)
	var recs []AuditRecord
	var home string
	out, er, err := runConfined(t, fixture(t, "terragrunt.sh"), withHome(t), rel.mock(t), collectAudit(&recs), func(c *Config) {
		home = c.Dir
	})
	if err == nil {
		t.Fatalf("expected the install to abort at GPG verification; got success\n%s", out)
	}
	for _, want := range []string{"URL not in allow-list: https://gruntwork.io/.well-known/pgp-key.txt", "GPG signature verification failed!"} {
		if !strings.Contains(er, want) {
			t.Errorf("stderr missing %q:\n%s", want, er)
		}
	}
	// gpg ran (it is allow-listed); it was the key fetch that was refused.
	ran := false
	for _, r := range recs {
		if r.Name == "gpg" {
			ran = true
			if strings.Contains(r.Reason, "blocked") {
				t.Errorf("gpg should be allow-listed; audit: %+v", r)
			}
		}
	}
	if !ran {
		t.Errorf("expected gpg --import to have run; records: %+v", recs)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".terragrunt", "bin", "terragrunt")); statErr == nil {
		t.Error("terragrunt was installed despite the failed signature verification")
	}

	rel = newTerragruntRelease(t)
	out, er, err = runConfined(t, fixture(t, "terragrunt.sh"), withHome(t), rel.mock(t), func(c *Config) {
		c.Args = []string{"--no-verify-sig"}
	})
	if err != nil {
		t.Fatalf("--no-verify-sig install failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	if !strings.Contains(out, "installed successfully") || strings.Contains(er, "blocked command") {
		t.Errorf("--no-verify-sig run:\n%s\n%s", out, er)
	}
}

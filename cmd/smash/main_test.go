package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	profilemanifest "github.com/rezen/smash/internal/manifest"
	"github.com/rezen/smash/internal/policy"
)

// write drops content at dir/name and returns the path.
func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// run invokes the CLI with -root and -audit pointed inside dir, so a test
// neither touches ./sandbox nor writes the audit trail to the test's stderr.
// It returns the audit log.
func run(t *testing.T, dir string, argv ...string) (string, error) {
	t.Helper()
	auditPath := filepath.Join(dir, "audit.log")
	full := append([]string{"-root", filepath.Join(dir, "sandbox"), "-audit", auditPath}, argv...)
	err := runCLI(full)
	b, rerr := os.ReadFile(auditPath)
	if rerr != nil && err == nil {
		t.Fatalf("no audit log written: %v", rerr)
	}
	return string(b), err
}

// TestInitPolicyRoundTrip is the loop -init-policy exists for: the file it
// writes must be one -policy accepts.
func TestInitPolicyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "policy.yaml")
	if err := runCLI([]string{"-init-policy", out}); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(out); err != nil {
		t.Fatalf("the generated policy does not load: %v", err)
	}
	script := write(t, dir, "s.sh", "echo hello\n")
	if _, err := run(t, dir, "-policy", out, script); err != nil {
		t.Fatalf("run under the generated policy: %v", err)
	}
	// -init-policy exits before anything else, so a stray script argument is
	// not run.
	if err := runCLI([]string{"-init-policy", filepath.Join(dir, "b.yaml"), "/nonexistent.sh"}); err != nil {
		t.Fatal(err)
	}
}

// TestPolicyFileSuppliesTheRun covers the whole point of the file: script,
// args, gate and mocks all come from it, with nothing on the command line.
func TestPolicyFileSuppliesTheRun(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "s.sh", "uname -s\necho \"arg=$1\"\nfrobnicate || echo \"denied=$?\"\n")
	pol := write(t, dir, "policy.yaml", `
script: `+filepath.Join(dir, "s.sh")+`
args: [--non-interactive]
commands:
  allow: [echo]
  disable: [frobnicate]
mocks:
  - match: {args: [uname, -s]}
    stdout: "Linux\n"
`)
	log, err := run(t, dir, "-policy", pol)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, want := range []string{"name: uname", "name: frobnicate", "disabled command"} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %q; got:\n%s", want, log)
		}
	}
}

// TestFlagsOverridePolicy is the precedence rule, and specifically that it is
// keyed off which flags were TYPED: -strict absent must not overwrite a
// policy's `strict: true` with the flag's false default.
func TestFlagsOverridePolicy(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "s.sh", "df -h >/dev/null 2>&1 || true\n")
	pol := write(t, dir, "policy.yaml", "strict: true\n")

	// The policy's strict survives the untouched -strict flag: df is neither
	// allow-listed nor inside the root, so a strict run blocks it.
	log, err := run(t, dir, "-policy", pol, script)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log, "blocked command: df") {
		t.Errorf("policy strict:true did not survive an unset -strict flag:\n%s", log)
	}
	// Typed, the flag wins the other way: df runs, flagged unlisted.
	log, err = run(t, dir, "-policy", pol, "-strict=false", script)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log, "blocked command: df") {
		t.Errorf("-strict=false did not override the policy:\n%s", log)
	}
	if !strings.Contains(log, "unlisted: true") {
		t.Errorf("df should have run flagged unlisted:\n%s", log)
	}
}

// TestCommandLineScriptWinsAsAUnit: naming a script on the command line
// replaces the policy's script AND its args, so a new script does not silently
// inherit arguments meant for the old one.
func TestCommandLineScriptWinsAsAUnit(t *testing.T) {
	dir := t.TempDir()
	// The scripts report through a file rather than stdout: echo is a shell
	// builtin, so it leaves no audit record to assert on.
	out := filepath.Join(dir, "said.txt")
	write(t, dir, "old.sh", "echo old > "+out+"\n")
	other := write(t, dir, "other.sh", "echo \"got=[$*]\" > "+out+"\n")
	pol := write(t, dir, "policy.yaml", "script: "+filepath.Join(dir, "old.sh")+"\nargs: [--from-policy]\n")

	said := func(t *testing.T, argv ...string) string {
		t.Helper()
		if _, err := run(t, dir, argv...); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	if got := said(t, "-policy", pol, other); got != "got=[]" {
		t.Errorf("got %q; a command-line script inherited the policy's args", got)
	}
	if got := said(t, "-policy", pol, other, "--typed"); got != "got=[--typed]" {
		t.Errorf("got %q, want got=[--typed]", got)
	}
	// With no script on the command line, both come from the file.
	if got := said(t, "-policy", pol); got != "old" {
		t.Errorf("got %q, want the policy's script to have run", got)
	}
}

// TestPolicyURLsValidated: a URL prefix with no scheme matches nothing, which
// fails closed but silently. The CLI takes its list from a user, so it says so.
func TestPolicyURLsValidated(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "s.sh", "true\n")
	pol := write(t, dir, "policy.yaml", "network:\n  urls: [example.com/pkg]\n")
	if _, err := run(t, dir, "-policy", pol, script); err == nil {
		t.Error("a scheme-less URL prefix was accepted")
	} else if !strings.Contains(err.Error(), "scheme") {
		t.Errorf("error = %v, want it to name the missing scheme", err)
	}
	if _, err := run(t, dir, "-urls", "example.com/pkg", script); err == nil {
		t.Error("a scheme-less -urls entry was accepted")
	}
}

func TestDNSServerValidationAndOverride(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "s.sh", "true\n")
	pol := write(t, dir, "policy.yaml", "network:\n  dns-server: not-an-ip\n")
	if _, err := run(t, dir, "-policy", pol, script); err == nil || !strings.Contains(err.Error(), "DNS server") {
		t.Errorf("invalid policy DNS server error = %v", err)
	}
	// A typed flag wins over the policy. Empty deliberately selects the system
	// resolver, and is distinct from an absent flag (which keeps the policy).
	if _, err := run(t, dir, "-policy", pol, "-dns-server", "", script); err != nil {
		t.Fatalf("empty -dns-server did not override the policy: %v", err)
	}
	if _, err := run(t, dir, "-dns-server", "dns.example", script); err == nil || !strings.Contains(err.Error(), "IP literal") {
		t.Errorf("hostname DNS server error = %v", err)
	}
}

func TestPolicyErrors(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "s.sh", "true\n")
	if err := runCLI([]string{"-policy", filepath.Join(dir, "missing.yaml"), script}); err == nil {
		t.Error("a missing policy file was ignored")
	}
	bad := write(t, dir, "bad.yaml", "strickt: true\n")
	if err := runCLI([]string{"-policy", bad, script}); err == nil {
		t.Error("an unknown policy key was ignored")
	}
	// No script anywhere is a usage error, not a panic.
	empty := write(t, dir, "empty.yaml", "strict: true\n")
	if err := runCLI([]string{"-policy", empty}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("err = %v, want a usage error", err)
	}
}

func TestProfileManifestAndEnforcedRun(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "profile.sh", "set -e\ndf -P / >/dev/null\n/bin/sh -c '/usr/bin/true'\n")
	pol := write(t, dir, "deny-profile.yaml", "strict: true\ncommands:\n  replace: true\n  disable: [df, sh, true]\n")
	manifestPath := filepath.Join(dir, "profile.yaml")
	log, err := run(t, dir, "-policy", pol, "-profile", "-profile-output", manifestPath, script)
	if err != nil {
		t.Fatalf("profile run: %v", err)
	}
	if strings.Contains(log, "blocked command") || strings.Contains(log, "disabled command") || strings.Contains(log, "unlisted command") {
		t.Fatalf("profile mode enforced a policy denial:\n%s", log)
	}
	m, err := profilemanifest.Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Commands, []string{"df", "sh", "true"}) {
		t.Errorf("profile commands = %v", m.Commands)
	}
	if len(m.Hosts) != 0 {
		t.Errorf("profile hosts = %v", m.Hosts)
	}
	// The manifest's evidence — the full audit trail — lands beside it,
	// regardless of where -audit pointed.
	sidecar, err := os.ReadFile(filepath.Join(dir, "profile.log"))
	if err != nil {
		t.Fatalf("profile audit log missing next to the manifest: %v", err)
	}
	if !strings.Contains(string(sidecar), "- name: df") {
		t.Errorf("profile audit log lacks the observed commands:\n%s", sidecar)
	}

	// The exact script is accepted. df is not on a deliberately empty policy
	// allow-list, so success also proves the generated command grant is active.
	log, err = run(t, dir, "-manifest", manifestPath, script)
	if err != nil {
		t.Fatalf("manifest run: %v", err)
	}
	if strings.Contains(log, "blocked command: df") {
		t.Fatalf("profiled command was blocked:\n%s", log)
	}

	if err := os.WriteFile(script, []byte("df -h / >/dev/null\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := run(t, dir, "-manifest", manifestPath, script); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Errorf("changed script error = %v", err)
	}
}

func TestProfileAndManifestAreExclusive(t *testing.T) {
	err := runCLI([]string{"-profile", "-manifest", "in.yaml", "script.sh"})
	if err == nil || !strings.Contains(err.Error(), "cannot be used together") {
		t.Errorf("error = %v", err)
	}
}

func TestProfileFlagTakesTheScriptAsPositionalArgument(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "installer.sh", "df -P / >/dev/null\n")
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	if _, err := run(t, dir, "-profile", script); err != nil {
		t.Fatalf("smash -profile SCRIPT: %v", err)
	}
	if _, err := profilemanifest.Load(filepath.Join(dir, "installer.manifest.yaml")); err != nil {
		t.Fatalf("default profile output: %v", err)
	}
}

// TestProfileBypassesDownloaderPolicyAndMocks: profiling runs curl through
// the shared in-process downloader with everything admitted — the hostile
// policy (deny-all URLs, a broken resolver, disabled + mocked curl) must not
// truncate discovery, and the generated manifest records what the response
// actually was: the redirect target host and the declared media type.
func TestProfileBypassesDownloaderPolicyAndMocks(t *testing.T) {
	body := []byte("\x1f\x8b\x08\x00tool-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "/tool", http.StatusFound)
		case "/tool":
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(body)
		case "/untyped":
			w.Header()["Content-Type"] = nil
			w.Write([]byte("bytes"))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	script := write(t, dir, "network.sh", "set -e\ncurl -fsSL "+srv.URL+"/redir -o tool.bin\n")
	pol := write(t, dir, "deny-network.yaml", "strict: true\ncommands:\n  disable: [curl]\nnetwork:\n  urls: []\n  dns-server: not-an-ip\nmocks:\n  - match: {name: [curl]}\n    exit: 9\n")
	manifestPath := filepath.Join(dir, "network.manifest.yaml")
	log, err := run(t, dir, "-policy", pol, "-profile", "-profile-output", manifestPath, script)
	if err != nil {
		t.Fatalf("unrestricted profile run: %v\n%s", err, log)
	}
	for _, denial := range []string{"disabled command", "URL not in allow-list", "unlisted command", "[sandbox]"} {
		if strings.Contains(log, denial) {
			t.Fatalf("profile mode enforced policy (%q):\n%s", denial, log)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "sandbox", "home", "tool.bin")) // the run's cwd is <root>/home
	if err != nil || !slices.Equal(got, body) {
		t.Errorf("downloaded body = %q, %v; the mock must not fire and the fetch must be in-process", got, err)
	}
	m, err := profilemanifest.Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Commands, []string{"curl"}) || !slices.Equal(m.Hosts, []string{"127.0.0.1"}) {
		t.Errorf("profile = commands %v, hosts %v", m.Commands, m.Hosts)
	}
	if m.URLs != nil {
		t.Errorf("profile urls = %v, want none — 127.0.0.1 is not a project-shaped GitHub host", m.URLs)
	}
	if !slices.Equal(m.MIMETypes, []string{"application/gzip"}) {
		t.Errorf("profile mime-types = %v, want the observed declared type", m.MIMETypes)
	}

	// A response body with no declared Content-Type poisons the list: writing
	// one would make enforcement deny the very script that was profiled.
	script = write(t, dir, "untyped.sh", "curl -fsS "+srv.URL+"/untyped -o x.bin\ncurl -fsSL "+srv.URL+"/tool -o tool.bin\n")
	manifestPath = filepath.Join(dir, "untyped.manifest.yaml")
	if log, err := run(t, dir, "-profile", "-profile-output", manifestPath, script); err != nil {
		t.Fatalf("untyped profile run: %v\n%s", err, log)
	}
	m, err = profilemanifest.Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if m.MIMETypes != nil {
		t.Errorf("mime-types = %v, want omitted after an untyped response body", m.MIMETypes)
	}
}

func TestProfileRecordsFailuresAndContinuesPastErrexit(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "fail.sh", "set -e\n/usr/bin/false\n/usr/bin/true\n")
	manifestPath := filepath.Join(dir, "fail.manifest.yaml")
	log, err := run(t, dir, "-profile", "-profile-output", manifestPath, script)
	if err != nil {
		t.Fatalf("profile stopped on an external command failure: %v\n%s", err, log)
	}
	if !strings.Contains(log, `name: "false"`) || !strings.Contains(log, "exit: 1") || !strings.Contains(log, `name: "true"`) {
		t.Fatalf("audit did not retain the failure and later command:\n%s", log)
	}
	m, err := profilemanifest.Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Commands, []string{"false", "true"}) {
		t.Errorf("profile commands = %v", m.Commands)
	}
}

func TestProfilePreservesFailureInConditions(t *testing.T) {
	dir := t.TempDir()
	script := write(t, dir, "condition.sh", "set -e\nif printf safe | grep -Eq '^/'; then\n  exit 42\nfi\n/usr/bin/true\n")
	manifestPath := filepath.Join(dir, "condition.manifest.yaml")
	log, err := run(t, dir, "-profile", "-profile-output", manifestPath, script)
	if err != nil {
		t.Fatalf("profile changed a false condition to success: %v\n%s", err, log)
	}
	if !strings.Contains(log, "name: grep") || !strings.Contains(log, "exit: 1") || !strings.Contains(log, `name: "true"`) {
		t.Fatalf("conditional status or subsequent discovery is wrong:\n%s", log)
	}
}

// TestResetRootRefusesForeignDirectories: -root is emptied on every run, so a
// mistyped one would recursively delete whatever the path names. Only a
// missing directory, an empty one, or a previous sandbox may be cleared.
func TestResetRootRefusesForeignDirectories(t *testing.T) {
	reset := func(root string) error {
		return resetRoot(root)
	}

	t.Run("missing", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "fresh")
		if err := reset(root); err != nil {
			t.Fatalf("a missing root should be created: %v", err)
		}
		for _, d := range []string{"home", "tmp"} {
			if fi, err := os.Stat(filepath.Join(root, d)); err != nil || !fi.IsDir() {
				t.Errorf("%s not created: %v", d, err)
			}
		}
		if b, err := os.ReadFile(filepath.Join(root, rootMarker)); err != nil || string(b) != rootMarkerContent {
			t.Errorf("root marker = %q, %v", b, err)
		}
	})

	t.Run("previous sandbox is reused", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "sandbox")
		if err := reset(root); err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(root, "home", "leftover")
		if err := os.MkdirAll(filepath.Dir(stale), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stale, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := reset(root); err != nil {
			t.Fatalf("a previous sandbox should be cleared: %v", err)
		}
		if _, err := os.Stat(stale); err == nil {
			t.Error("the previous run's files should be gone")
		}
	})

	t.Run("home and tmp are not an ownership proof", func(t *testing.T) {
		root := t.TempDir()
		keep := filepath.Join(root, "home", "important")
		if err := os.MkdirAll(filepath.Dir(keep), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(root, "tmp"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keep, []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := reset(root); err == nil {
			t.Fatal("an unmarked directory containing home and tmp must be refused")
		}
		if b, err := os.ReadFile(keep); err != nil || string(b) != "keep" {
			t.Fatalf("unrelated data changed: %q, %v", b, err)
		}
	})

	t.Run("someone else's directory is refused", func(t *testing.T) {
		root := t.TempDir()
		keep := filepath.Join(root, "main.go")
		if err := os.WriteFile(keep, []byte("package main\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		err := reset(root)
		if err == nil {
			t.Fatal("a directory with other contents must not be emptied")
		}
		if !strings.Contains(err.Error(), "no valid "+rootMarker+" marker") {
			t.Errorf("unhelpful error: %v", err)
		}
		if _, statErr := os.Stat(keep); statErr != nil {
			t.Errorf("the existing file was deleted anyway: %v", statErr)
		}
	})

	t.Run("a file is refused", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "notadir")
		if err := os.WriteFile(root, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := reset(root); err == nil {
			t.Error("a plain file must not be treated as a sandbox root")
		}
	})

	t.Run("invalid marker is refused", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, rootMarker), []byte("not smash\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := reset(root); err == nil {
			t.Fatal("an invalid ownership marker must be refused")
		}
	})

	t.Run("root symlink is refused", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "target")
		if err := os.Mkdir(target, 0o755); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(dir, "root")
		if err := os.Symlink(target, root); err != nil {
			t.Fatal(err)
		}
		if err := reset(root); err == nil {
			t.Fatal("a root symlink must be refused")
		}
	})
}

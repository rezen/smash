package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// TestResetRootRefusesForeignDirectories: -root is emptied on every run, so a
// mistyped one would recursively delete whatever the path names. Only a
// missing directory, an empty one, or a previous sandbox may be cleared.
func TestResetRootRefusesForeignDirectories(t *testing.T) {
	reset := func(root string) error {
		return resetRoot(root, filepath.Join(root, "home"), filepath.Join(root, "tmp"))
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
	})

	t.Run("previous sandbox is reused", func(t *testing.T) {
		root := t.TempDir()
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
		if !strings.Contains(err.Error(), "not a previous sandbox") {
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
}

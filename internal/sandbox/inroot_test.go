package sandbox

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The escape hatch — a program that resolves inside the sandbox root may run —
// exists so a freshly installed binary can execute. Writing an executable into
// the root is not an exotic capability, though: it is what every installer
// does. These tests pin the hatch to what it is for, because the gate reasons
// about argv[0] while the kernel runs whatever a `#!` line names, and a script
// dropped in the root was once the general way past the sensitive list, past
// Strict and past Denied — none of which ever see the interpreter's name.

// installScript writes an executable file into the sandbox root and returns
// the shell fragment that runs it, the way an installer would.
func installScript(body string) string {
	return "cat > \"$HOME/x\" <<'SMASH_EOF'\n" + body + "SMASH_EOF\nchmod +x \"$HOME/x\"\n\"$HOME/x\"\n"
}

// TestInRootShellScriptIsInterpretedConfined: a shell script in the root runs,
// so an installer's shell wrapper still works — but it is parsed and run in the
// confined sub-runner, so the commands inside it face the whole stack again
// rather than a real host shell.
func TestInRootShellScriptIsInterpretedConfined(t *testing.T) {
	out, er, _ := runConfined(t, installScript("#!/bin/bash\necho inner-ran\ndpkg --version\n"), withHome(t))
	if !strings.Contains(out, "inner-ran") {
		t.Errorf("the script should still run; stdout=%q stderr=%q", out, er)
	}
	if !strings.Contains(er, "interpreting confined") {
		t.Errorf("expected the script to be interpreted, not exec'd; stderr=%q", er)
	}
	if !strings.Contains(er, "blocked command: dpkg") {
		t.Errorf("commands inside an in-root script must be re-enforced; stderr=%q", er)
	}
}

// TestInRootScriptCannotEscapeStrictOrDeny: the three controls a user sets
// expecting them to be absolute stay absolute. Under -strict with the shells
// disabled outright, a `#!` script in the root must not become a way to run
// anything at all.
func TestInRootScriptCannotEscapeStrictOrDeny(t *testing.T) {
	strictNoShells := func(c *Config) {
		c.Strict = true
		c.Disable("bash", "sh")
	}
	out, er, err := runConfined(t, installScript("#!/bin/bash\necho ESCAPED\n"), withHome(t), strictNoShells)
	if err == nil || strings.Contains(out, "ESCAPED") {
		t.Fatalf("a disabled interpreter must not run the script; err=%v stdout=%q stderr=%q", err, out, er)
	}
	if !strings.Contains(er, "disabled command: /bin/bash") {
		t.Errorf("the denial should name the interpreter, not the file; stderr=%q", er)
	}
}

// TestInRootScriptJudgedByItsInterpreter: a script for an interpreter the
// sandbox cannot interpret itself is judged exactly as if that interpreter had
// been invoked directly — sensitive, so blocked until allow-listed. `#!/usr/bin/env
// python3` names python3, not env.
func TestInRootScriptJudgedByItsInterpreter(t *testing.T) {
	script := installScript("#!/usr/bin/env python3\nprint('ESCAPED')\n")
	out, er, err := runConfined(t, script, withHome(t))
	if err == nil || strings.Contains(out, "ESCAPED") {
		t.Fatalf("expected the interpreter to be gated; err=%v stdout=%q stderr=%q", err, out, er)
	}
	if !strings.Contains(er, "blocked command: python3") {
		t.Errorf("the denial should name python3; stderr=%q", er)
	}

	// Allow-listing the interpreter is the deliberate grant that lifts it.
	allowPython := func(c *Config) { c.Allowed = c.Allowed.With("python3") }
	if out, er, err := runConfined(t, script, withHome(t), allowPython); err != nil || !strings.Contains(out, "ESCAPED") {
		t.Errorf("allow-listing python3 should let it run; err=%v stdout=%q stderr=%q", err, out, er)
	}
}

// TestInRootExecutionIsFlagged: a program the script installed still runs —
// that is the point of the hatch — but never silently. Here the interpreter is
// allow-listed and is not a shell, so the file is exec'd for real, and the
// audit record has to say how it got past the gate.
func TestInRootExecutionIsFlagged(t *testing.T) {
	var recs []AuditRecord
	script := installScript("#!/usr/bin/awk -f\nBEGIN { print \"awk-ran\" }\n")
	out, er, err := runConfined(t, script, withHome(t), collectAudit(&recs))
	if err != nil || !strings.Contains(out, "awk-ran") {
		t.Fatalf("an in-root program with an allow-listed interpreter should run; err=%v stdout=%q stderr=%q", err, out, er)
	}
	for _, r := range recs {
		if r.Name == "x" {
			if !r.InRoot {
				t.Errorf("the record for the in-root program should be flagged; %+v", r)
			}
			return
		}
	}
	t.Errorf("no audit record for the in-root program; records=%+v", recs)
}

// TestFetchCannotWriteOutsideRoot: the in-process curl is the one write the
// sandbox performs itself, so it is the one it can confine. An allow-listed URL
// is not a licence to write to an arbitrary path.
func TestFetchCannotWriteOutsideRoot(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload"))
	}))
	defer srv.Close()
	allowLocal := func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }

	outside := filepath.Join(t.TempDir(), "stolen")
	_, er, err := runConfined(t, "curl -fsS "+srv.URL+"/x -o "+outside, withHome(t), allowLocal)
	if err == nil {
		t.Fatalf("a fetch writing outside the root must fail; stderr=%q", er)
	}
	if !strings.Contains(er, "refusing to write outside the sandbox root") {
		t.Errorf("expected the sandbox's own diagnostic; stderr=%q", er)
	}
	if _, statErr := os.Stat(outside); statErr == nil {
		t.Errorf("%s was created anyway", outside)
	}

	// The same fetch inside the root is exactly what the sandbox is for.
	out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/x -o inside.txt && cat inside.txt", withHome(t), allowLocal)
	if err != nil || !strings.Contains(out, "payload") {
		t.Errorf("a fetch into the root should work; err=%v stdout=%q stderr=%q", err, out, er)
	}
}

// TestAuditRecordsWrapperChain: enforcement forgets the wrappers on purpose —
// a guard must see the real command — but the log must not. `sudo rm` and `rm`
// are the same command to the gate and very different events to a reader.
func TestAuditRecordsWrapperChain(t *testing.T) {
	var recs []AuditRecord
	runConfined(t, "sudo env FOO=1 id -un", withHome(t), collectAudit(&recs))
	for _, r := range recs {
		if r.Name != "id" {
			continue
		}
		if got := strings.Join(r.Wrappers, "+"); got != "sudo+env" {
			t.Errorf("wrappers = %q, want \"sudo+env\"", got)
		}
		return
	}
	t.Errorf("no record for the unwrapped command; records=%+v", recs)
}

package sandbox

import (
	"strings"
	"testing"
)

// TestTrapSignalSpecs pins the ninth interpreter patch. Upstream mvdan/sh
// understood only ERR and EXIT as signal specs and failed `trap` with status 2
// for anything else, so mole's
//
//	trap 'cleanup_installer' EXIT
//	trap 'cleanup_installer; exit 130' INT TERM
//
// aborted the installer at the second line under `set -e`. bash accepts a
// signal name with or without the SIG prefix in any case, a signal number, and
// EXIT (0) and ERR. Every expectation here was checked against /bin/bash.
func TestTrapSignalSpecs(t *testing.T) {
	cases := []struct {
		script string
		want   string // stdout, or "" when the script must fail
	}{
		// The mole case: registering a signal trap is not an error.
		{"set -e\ntrap 'echo cleanup' INT TERM\necho ran\n", "ran\n"},
		// Every spelling bash takes: bare name, SIG prefix, either case, number.
		{"set -e\ntrap 'echo x' sigquit\ntrap 'echo y' SIGHUP\ntrap 'echo z' 2\necho ran\n", "ran\n"},
		{"set -e\ntrap 'echo x' HUP INT QUIT TERM USR1 USR2 WINCH CHLD PIPE ALRM\necho ran\n", "ran\n"},
		// The pseudo-signals keep working, including EXIT spelled as 0.
		{"trap 'echo bye' EXIT\necho hi\n", "hi\nbye\n"},
		{"trap 'echo bye' 0\necho hi\n", "hi\nbye\n"},
		{"set -e\ntrap 'echo caught' ERR\nfalse || true\necho ran\n", "ran\n"},
		// Recorded, never delivered: no signal reaches an in-process script, so
		// a handler for one must not run just because the script ended.
		{"trap 'echo int' INT\necho done\n", "done\n"},
		{"trap '' INT\necho done\n", "done\n"},
		// A spec bash rejects is still rejected, and still aborts under `set -e`.
		// (The status is upstream's 2 rather than bash's 1; either way `set -e`
		// ends the script, which is the behaviour installers depend on.)
		{"set -e\ntrap 'echo z' BOGUS\necho unreachable\n", ""},
		{"set -e\ntrap 'echo z' SIGBOGUS\necho unreachable\n", ""},
	}
	for _, tc := range cases {
		out, er, err := runConfined(t, tc.script)
		if tc.want == "" {
			if err == nil || !strings.Contains(er, "invalid signal specification") {
				t.Errorf("%q\n  want invalid-signal failure, got out=%q err=%v stderr=%q", tc.script, out, err, er)
			}
			continue
		}
		if err != nil || out != tc.want {
			t.Errorf("%q\n  got out=%q err=%v stderr=%q (want %q)", tc.script, out, err, er, tc.want)
		}
	}
}

// TestTrapListsSignalTraps pins the listing side of the same patch: a bare
// `trap` reports the signal traps a script registered, so an audit can see what
// it asked for. The set and the order match bash — EXIT first, then the signals
// under their SIG names — but the callback is quoted the way upstream already
// quotes EXIT and ERR, with Go's %q rather than bash's single quotes.
func TestTrapListsSignalTraps(t *testing.T) {
	const script = "trap 'echo a' INT\ntrap 'echo b' EXIT\ntrap '' TERM\ntrap 'echo h' 1\ntrap\n" +
		"echo ---\ntrap - INT\ntrap\n"
	want := strings.Join([]string{
		`trap -- "echo b" EXIT`,
		`trap -- "echo h" SIGHUP`,
		`trap -- "echo a" SIGINT`,
		`trap -- "" SIGTERM`,
		`---`,
		`trap -- "echo b" EXIT`,
		`trap -- "echo h" SIGHUP`,
		`trap -- "" SIGTERM`,
		`b`, // the EXIT trap firing last
		``,
	}, "\n")
	out, er, err := runConfined(t, script)
	if err != nil || out != want {
		t.Errorf("got out=%q err=%v stderr=%q\nwant %q", out, err, er, want)
	}
}

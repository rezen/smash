package sandbox

import (
	"strings"
	"testing"
)

// TestErrexitCompoundBodies pins the third interpreter patch. Upstream mvdan/sh
// re-judges errexit on a compound command's own exit status, so under `set -e`
// an exempt failure as the last statement of an if/then body — terragrunt's
// `! supports_signature_verification "$version" && warn …` — exited the
// script. bash only judges the statement itself: compound bodies (if, { },
// for, while, case) inherit their last statement's exemption, while a failing
// function call or subshell is a command of its own and still exits. Every
// expectation here was checked against /bin/bash.
func TestErrexitCompoundBodies(t *testing.T) {
	cases := []struct {
		script string
		after  bool // does "after" get printed?
	}{
		{"if true; then false && true; fi; echo after", true},
		{"if true; then ! true; fi; echo after", true},
		{"if true; then ! true && echo warn; fi; echo after", true},
		{"{ false && true; }; echo after", true},
		{"for i in 1; do false && true; done; echo after", true},
		{"while true; do false && true; break; done; echo after", true},
		{"case x in x) false && true;; esac; echo after", true},
		{"if true; then false | true; fi; echo after", true},
		{"f() { if true; then ! true && echo warn; fi; echo in-f; }; f; echo after", true},
		// Still fatal: a real failure inside the body, a failing function
		// call, a failing subshell, a failing command substitution.
		{"if true; then false; fi; echo after", false},
		{"f() { false && true; }; f; echo after", false},
		{"f() { if true; then ! true && echo warn; fi; }; f; echo after", false},
		{"( false && true ); echo after", false},
		{"x=$(false && true); echo after", false},
	}
	for _, tc := range cases {
		out, er, err := runConfined(t, "set -e\n"+tc.script+"\n")
		got := strings.Contains(out, "after")
		if got != tc.after || (err == nil) != tc.after {
			t.Errorf("%s\n  printed after=%v err=%v (want after=%v)\n  stderr=%q", tc.script, got, err, tc.after, er)
		}
	}
}

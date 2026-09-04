package sandbox

import (
	"strings"
	"testing"
)

// TestTestClauseShortCircuit pins the fifth interpreter patch. Upstream
// mvdan/sh expands and evaluates both operands of `&&` and `||` inside
// `[[ ]]` before combining them, so under `set -u` bun's
// `[[ $# = 2 && $2 = debug-info ]]` died with "2: unbound variable" when the
// script had no arguments. bash short-circuits: the right operand is never
// expanded when the left one decides the result. Every expectation here was
// checked against /bin/bash.
func TestTestClauseShortCircuit(t *testing.T) {
	cases := []struct {
		script string
		want   string // stdout, or "" when the script must fail
	}{
		// The right operand is skipped, so its unset positional is never expanded.
		{`[[ $# = 2 && $2 = x ]] && echo y || echo n`, "n\n"},
		{`[[ 1 = 1 || $2 = x ]] && echo y || echo n`, "y\n"},
		{`[[ -n ${1:-} && $1 = x ]] && echo y || echo n`, "n\n"},
		{`[[ 1 = 2 || ( 1 = 2 && $2 = x ) ]] && echo y || echo n`, "n\n"},
		{`[[ 1 = 1 && ( 1 = 1 || $2 = x ) ]] && echo y || echo n`, "y\n"},
		// Skipped operands have no side effects either.
		{`i=0; [[ 1 = 2 && $((i++)) = 0 ]]; echo $i`, "0\n"},
		{`i=0; [[ 1 = 1 || $((i++)) = 0 ]]; echo $i`, "0\n"},
		{`i=0; [[ 1 = 1 && $((i++)) = 0 ]]; echo $i`, "1\n"},
		{`i=0; [[ 1 = 2 || $((i++)) = 0 ]]; echo $i`, "1\n"},
		// The right operand is evaluated when the left does not decide.
		{`set -- a x; [[ $# = 2 && $2 = x ]] && echo y || echo n`, "y\n"},
		{`[[ 1 = 2 || 2 = 2 ]] && echo y || echo n`, "y\n"},
		{`[[ 1 = 1 && 2 = 3 ]] && echo y || echo n`, "n\n"},
		{`v=abc; [[ -n $v && $v =~ ^a(b) ]] && echo "${BASH_REMATCH[1]}"`, "b\n"},
		// ... and still trips nounset then.
		{`[[ 1 = 1 && $2 = x ]]`, ""},
		{`[[ 1 = 2 || $2 = x ]]`, ""},
	}
	for _, tc := range cases {
		out, er, err := runConfined(t, "set -u\n"+tc.script+"\n")
		if tc.want == "" {
			if err == nil || !strings.Contains(er, "unbound variable") {
				t.Errorf("%s\n  want unbound-variable failure, got out=%q err=%v stderr=%q", tc.script, out, err, er)
			}
			continue
		}
		if err != nil || out != tc.want {
			t.Errorf("%s\n  got out=%q err=%v stderr=%q (want %q)", tc.script, out, err, er, tc.want)
		}
	}
}

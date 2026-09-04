package sandbox

import (
	"strings"
	"testing"
)

// TestIndirectExpansion pins the sixth interpreter patch. Upstream mvdan/sh
// returns the value of a plain indirection ${!name} and ignores any operator
// after it, so bun's `install_dir=${!install_env:-$HOME/.bun}` expanded to
// "" with $BUN_INSTALL unset and the installer went on to write /bin/bun.zip.
// bash applies the operator to the target variable, and under `set -u`
// objects to an unset target. Every expectation here was checked against
// /bin/bash.
func TestIndirectExpansion(t *testing.T) {
	cases := []struct {
		script string
		want   string // stdout, or "" when the script must fail
	}{
		// The operator applies to the target.
		{`v=U; echo "[${!v:-d}]"`, "[d]\n"},
		{`v=U; echo "[${!v-d}]"`, "[d]\n"},
		{`v=U; U=; echo "[${!v:-d}]"`, "[d]\n"},
		{`v=U; U=; echo "[${!v-d}]"`, "[]\n"},
		{`v=U; U=x; echo "[${!v:-d}]"`, "[x]\n"},
		{`v=U; U=x; echo "[${!v:+alt}]"`, "[alt]\n"},
		{`v=U; echo "[${!v:+alt}]"`, "[]\n"},
		{`v=U; U=; echo "[${!v?msg}]"`, "[]\n"},
		{`v=U; U=abcd; echo "[${!v:1:2}] [${!v#a}] [${!v/b/X}]"`, "[bc] [bcd] [aXcd]\n"},
		{`a=(1 2); v=a[1]; echo "[${!v:-d}]"`, "[2]\n"},
		{`a=(1 2); v=a[5]; echo "[${!v:-d}]"`, "[d]\n"},
		// Unset or empty name: the target is unset.
		{`unset v; echo "[${!v:-d}]"`, "[d]\n"},
		{`v=; echo "[${!v:-d}]"`, "[d]\n"},
		// The plain form still works, and honours set -u on the target.
		{`v=U; U=x; echo "[${!v}]"`, "[x]\n"},
		{`v=U; echo "[${!v}]"`, "[]\n"},
		{`set -u; v=U; U=; echo "[${!v}]"`, "[]\n"},
		{`set -u; v=U; echo "[${!v:-d}]"`, "[d]\n"},
		{`set -u; v=U; echo "[${!v}]"`, ""},
		// Prefix and key listings are not indirections.
		{`AB1=1 AB2=2; echo "[${!AB@}]"`, "[AB1 AB2]\n"},
		{`a=(x y); echo "[${!a[@]}]"`, "[0 1]\n"},
	}
	for _, tc := range cases {
		out, er, err := runConfined(t, tc.script+"\n")
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

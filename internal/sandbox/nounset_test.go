package sandbox

import (
	"strings"
	"testing"
)

// TestNounsetUnusedWord pins the fourth interpreter patch. Upstream mvdan/sh
// expands the word of ${v-w}, ${v+w}, ${v?w}, ${v=w} and their ":" variants
// before deciding whether it is used, so under `set -u` ollama's
// `VER_PARAM="${OLLAMA_VERSION:+?version=$OLLAMA_VERSION}"` died with
// "OLLAMA_VERSION: unbound variable". bash only expands the word when it is
// used. Every expectation here was checked against /bin/bash.
func TestNounsetUnusedWord(t *testing.T) {
	cases := []struct {
		script string
		want   string // stdout, or "" when the script must fail
	}{
		// The word is not used, so its unset variable is never expanded.
		{`unset v u; echo "[${v:+x$u}]"`, "[]\n"},
		{`unset v u; echo "[${v+x$u}]"`, "[]\n"},
		{`v=; unset u; echo "[${v:+x$u}]"`, "[]\n"},
		{`v=1; unset u; echo "[${v:-x$u}]"`, "[1]\n"},
		{`v=1; unset u; echo "[${v-x$u}]"`, "[1]\n"},
		{`v=; unset u; echo "[${v-x$u}]"`, "[]\n"},
		{`v=1; unset u; echo "[${v:?x$u}]"`, "[1]\n"},
		{`v=1; unset u; echo "[${v:=x$u}]"`, "[1]\n"},
		{`unset u; a=(1 2); echo "[${a[@]:-x$u}]"`, "[1 2]\n"},
		// The word is used, and the nested expansion still counts.
		{`v=1 u=2; echo "[${v:+x$u}]"`, "[x2]\n"},
		{`unset v; u=2; echo "[${v:-x$u}]"`, "[x2]\n"},
		{`unset v; u=2; echo "[${v:=x$u}]$v"`, "[x2]x2\n"},
		{`v=1; unset u; echo "[${v:+x$u}]"`, ""},
		{`unset v u; echo "[${v:-x$u}]"`, ""},
		{`unset v u; echo "[${v:?x$u}]"`, ""},
		{`unset v u; echo "[${v:=x$u}]"`, ""},
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

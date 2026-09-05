package tool

import (
	"strings"
	"testing"
)

const abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestMktempPattern(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"tmp.XXXXXXXXXX", "tmp.*"},
		{"archive.XXXX.tar", "archive.*.tar"},
		{"portable", "portable.*"},
	} {
		got, err := mktempPattern(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("mktempPattern(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	if _, err := mktempPattern("bad.XX"); err == nil {
		t.Error("two-X template should fail")
	}
}

func TestParseChecksumLine(t *testing.T) {
	digest, name, ok := parseChecksumLine("\\" + abcSHA256 + "  dir\\\\line\\nname")
	if !ok || digest != abcSHA256 || name != "dir\\line\nname" {
		t.Fatalf("got digest=%q name=%q ok=%v", digest, name, ok)
	}
	for _, line := range []string{"", abcSHA256 + " abc", strings.Repeat("z", 64) + "  abc"} {
		if _, _, ok := parseChecksumLine(line); ok {
			t.Errorf("malformed line accepted: %q", line)
		}
	}
}

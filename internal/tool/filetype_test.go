package tool

import "testing"

// tarPeek builds the head of a POSIX tar stream: zeros with the ustar magic
// at offset 257, which is inside the 512-byte sniff window.
func tarPeek() []byte {
	b := make([]byte, 512)
	copy(b[257:], "ustar")
	return b
}

func TestRefineSniff(t *testing.T) {
	octet := "application/octet-stream"
	for _, tc := range []struct {
		name    string
		sniffed string
		peek    []byte
		want    string
	}{
		{"tar", octet, tarPeek(), "application/x-tar"},
		{"xz", octet, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00, 1, 2}, "application/x-xz"},
		{"zstd", octet, []byte{0x28, 0xB5, 0x2F, 0xFD, 0, 0}, "application/zstd"},
		{"bzip2", octet, []byte("BZh91AY&SY"), "application/x-bzip2"},
		{"7z", octet, []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, "application/x-7z-compressed"},
		{"elf", octet, []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}, "application/x-executable"},
		{"mach-o 64", octet, []byte{0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1}, "application/x-mach-binary"},
		{"mach-o fat", octet, []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2}, "application/x-mach-binary"},
		{"java class is not a fat binary", octet, []byte{0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 65}, octet},
		{"deb", octet, []byte("!<arch>\ndebian-binary   "), "application/vnd.debian.binary-package"},
		{"ar", octet, []byte("!<arch>\nfoo.o           "), "application/x-archive"},
		{"rpm", octet, []byte{0xED, 0xAB, 0xEE, 0xDB, 3, 0}, "application/x-rpm"},
		{"xar (macOS pkg)", octet, []byte("xar!\x00\x1c"), "application/x-xar"},
		{"pe", octet, []byte("MZ\x90\x00\x03"), "application/vnd.microsoft.portable-executable"},
		{"unrecognized binary stays octet-stream", octet, []byte{0x00, 0x01, 0x02, 0x03}, octet},
		{"short peek stays octet-stream", octet, []byte{0xFD}, octet},
		{"shell shebang", "text/plain", []byte("#!/bin/sh\necho hi\n"), "application/x-shellscript"},
		{"env bash shebang", "text/plain", []byte("#!/usr/bin/env bash\nset -e\n"), "application/x-shellscript"},
		{"python shebang", "text/plain", []byte("#!/usr/bin/env python3\nprint()\n"), "text/x-python"},
		{"plain text stays plain", "text/plain", []byte("just words\n"), "text/plain"},
		{"unknown interpreter stays plain", "text/plain", []byte("#!/opt/weird/frob\n"), "text/plain"},
		{"named types are never touched", "text/html", []byte("MZ.."), "text/html"},
	} {
		if got := refineSniff(tc.sniffed, tc.peek); got != tc.want {
			t.Errorf("%s: refineSniff = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestRefinedSniffsPassTheGate: every refined type must remain acceptable
// wherever its unrefined ancestor was — the refinement is observability, not
// a new denial surface.
func TestRefinedSniffsPassTheGate(t *testing.T) {
	for sniffed := range binarySniffs {
		if !sniffAllowed(allowOnly("application/octet-stream"), "application/octet-stream", sniffed) {
			t.Errorf("%s: a refined binary type must pass where octet-stream passed", sniffed)
		}
	}
	for sniffed := range scriptSniffs {
		if !sniffAllowed(allowOnly("text/x-shellscript"), "text/x-shellscript", sniffed) {
			t.Errorf("%s: a refined script type must pass under a text-ish declaration", sniffed)
		}
	}
}

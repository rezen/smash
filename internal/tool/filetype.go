package tool

// http.DetectContentType stops at application/octet-stream for most of what
// installers actually download — tar, xz, zstd, native executables — and at
// text/plain for every script. refineSniff looks at the same peeked bytes
// with a magic-number table and reports the concrete file type, so the audit
// trail answers "what did the asset turn out to be" even when the server
// only said octet-stream.

import (
	"bytes"
	"encoding/binary"
	"path/filepath"
	"strings"

	"github.com/rezen/smash/internal/shell"
)

// refineSniff sharpens a DetectContentType verdict using magic numbers over
// the same peeked bytes. Only the two indistinct verdicts are refined —
// application/octet-stream by binary signatures, text/plain by shebang —
// everything DetectContentType already names is returned unchanged.
func refineSniff(sniffed string, peek []byte) string {
	switch sniffed {
	case "application/octet-stream":
		if t := binaryFileType(peek); t != "" {
			return t
		}
	case "text/plain":
		if t := scriptFileType(peek); t != "" {
			return t
		}
	}
	return sniffed
}

// binarySniffs is every type binaryFileType can report. The MIME gate treats
// them like the octet-stream they were sniffed from (see sniffAllowed): the
// refinement adds observability, never new denials.
var binarySniffs = map[string]bool{
	"application/x-tar":                             true,
	"application/x-xz":                              true,
	"application/zstd":                              true,
	"application/x-bzip2":                           true,
	"application/x-7z-compressed":                   true,
	"application/x-lz4":                             true,
	"application/x-compress":                        true,
	"application/x-executable":                      true,
	"application/x-mach-binary":                     true,
	"application/vnd.microsoft.portable-executable": true,
	"application/vnd.debian.binary-package":         true,
	"application/x-archive":                         true,
	"application/x-rpm":                             true,
	"application/x-xar":                             true,
}

// binaryFileType recognizes the archive, compressor, package and executable
// formats DetectContentType lumps into octet-stream. "" means unrecognized.
func binaryFileType(peek []byte) string {
	has := func(prefix ...byte) bool { return bytes.HasPrefix(peek, prefix) }
	switch {
	case len(peek) >= 262 && string(peek[257:262]) == "ustar":
		return "application/x-tar"
	case has(0xFD, '7', 'z', 'X', 'Z', 0x00):
		return "application/x-xz"
	case has(0x28, 0xB5, 0x2F, 0xFD):
		return "application/zstd"
	case len(peek) >= 4 && has('B', 'Z', 'h') && peek[3] >= '1' && peek[3] <= '9':
		return "application/x-bzip2"
	case has('7', 'z', 0xBC, 0xAF, 0x27, 0x1C):
		return "application/x-7z-compressed"
	case has(0x04, 0x22, 0x4D, 0x18):
		return "application/x-lz4"
	case has(0x1F, 0x9D):
		return "application/x-compress"
	case has(0x7F, 'E', 'L', 'F'):
		return "application/x-executable"
	case has(0xFE, 0xED, 0xFA, 0xCE), has(0xFE, 0xED, 0xFA, 0xCF),
		has(0xCE, 0xFA, 0xED, 0xFE), has(0xCF, 0xFA, 0xED, 0xFE):
		return "application/x-mach-binary"
	case has(0xCA, 0xFE, 0xBA, 0xBE) && len(peek) >= 8 &&
		binary.BigEndian.Uint32(peek[4:8]) <= 8:
		// The magic is shared with Java class files, where these four bytes
		// are a version well above any plausible fat-binary arch count.
		return "application/x-mach-binary"
	case bytes.HasPrefix(peek, []byte("!<arch>\n")):
		if bytes.Contains(peek, []byte("debian-binary")) {
			return "application/vnd.debian.binary-package"
		}
		return "application/x-archive"
	case has(0xED, 0xAB, 0xEE, 0xDB):
		return "application/x-rpm"
	case has('x', 'a', 'r', '!'):
		return "application/x-xar"
	case has('M', 'Z'):
		return "application/vnd.microsoft.portable-executable"
	}
	return ""
}

// scriptSniffs is every type scriptFileType can report. Under the MIME gate
// they stand in for the text/plain they were sniffed from (see sniffAllowed).
var scriptSniffs = map[string]bool{
	"application/x-shellscript": true,
	"text/x-python":             true,
	"text/x-perl":               true,
	"text/x-ruby":               true,
	"text/javascript":           true,
}

// scriptFileType names a shebanged script by its interpreter. "" means no
// shebang, or one this table does not care to distinguish from plain text.
func scriptFileType(peek []byte) string {
	line, _, _ := strings.Cut(string(peek), "\n")
	interp, ok := shell.Interpreter(line)
	if !ok {
		return ""
	}
	base := filepath.Base(interp)
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "csh", "tcsh", "fish":
		return "application/x-shellscript"
	}
	switch {
	case strings.HasPrefix(base, "python"):
		return "text/x-python"
	case strings.HasPrefix(base, "perl"):
		return "text/x-perl"
	case strings.HasPrefix(base, "ruby"):
		return "text/x-ruby"
	case base == "node" || base == "nodejs" || base == "deno" || base == "bun":
		return "text/javascript"
	}
	return ""
}

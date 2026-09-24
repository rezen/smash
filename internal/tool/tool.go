// Package tool implements selected command-line tools in-process. These tools
// behave consistently across hosts and execute inside the sandbox's policy and
// audit middleware instead of spawning native binaries.
package tool

import (
	"context"
	"fmt"
	"io"

	"mvdan.cc/sh/v3/interp"
)

var names = map[string]bool{
	"base64":    true,
	"curl":      true,
	"mktemp":    true,
	"sha256sum": true,
	"wget":      true,
}

// Is reports whether name is implemented by this package.
func Is(name string) bool { return names[name] }

// Failure is an in-process tool's exit status and diagnostic. The sandbox
// aliases this type so its auditor can distinguish policy/tool failures from a
// native command's ordinary non-zero exit.
type Failure struct {
	Code int
	Msg  string
}

func (f *Failure) Error() string { return f.Msg }
func (f *Failure) Unwrap() error { return interp.ExitStatus(f.Code) }

// Failf writes a diagnostic and returns it with the requested exit status.
func Failf(w io.Writer, code int, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(w, msg)
	return &Failure{Code: code, Msg: msg}
}

// ResponseNote carries what a downloader's response looked like out to the
// sandbox's audit layer, the way the command gate's note carries its
// verdicts. The auditor attaches one to the context; runDownloader fills it
// in for any response — the media-type fields whenever a body came back,
// whether or not a MIME gate is enforcing.
type ResponseNote struct {
	ContentType string   // declared Content-Type, parameters stripped; "" when absent or unparseable
	Sniffed     string   // what the first body bytes are: http.DetectContentType sharpened by refineSniff (tar/xz/executables/shebangs…)
	Via         []string // full URL of every response hop, initial request first, deduped
}

type responseNoteKey struct{}

// WithResponseNote attaches a fresh note to ctx and returns it for reading
// after the command completes.
func WithResponseNote(ctx context.Context) (context.Context, *ResponseNote) {
	n := &ResponseNote{}
	return context.WithValue(ctx, responseNoteKey{}, n), n
}

// ResponseNoteFrom returns the note attached to ctx, or nil.
func ResponseNoteFrom(ctx context.Context) *ResponseNote {
	n, _ := ctx.Value(responseNoteKey{}).(*ResponseNote)
	return n
}

// Package tool implements selected command-line tools in-process. These tools
// behave consistently across hosts and execute inside the sandbox's policy and
// audit middleware instead of spawning native binaries.
package tool

import (
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

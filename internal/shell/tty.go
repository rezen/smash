package shell

import (
	"io"
	"os"
)

// SameOpenFile reports whether w writes to the same open file as f — the
// check that picks the terminal-facing member of a pipeline. A writer that
// is not an *os.File never matches.
func SameOpenFile(w io.Writer, f *os.File) bool {
	wf, ok := w.(*os.File)
	if !ok || wf == nil || f == nil {
		return false
	}
	if wf == f {
		return true
	}
	a, err := wf.Stat()
	if err != nil {
		return false
	}
	b, err := f.Stat()
	return err == nil && os.SameFile(a, b)
}

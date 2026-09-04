package sandbox

// Emulation optionally fakes a target-OS environment so a Linux-only installer
// (e.g. get-docker) can be exercised on a non-Linux host. The zero value does
// nothing. It reuses the sandbox primitives: an exec middleware (fake `uname`)
// and the open/stat/access handlers (virtual files like /etc/os-release).
// Privilege wrappers (sudo/doas) are handled generally by unwrapMiddleware.

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"
)

// Emulation describes the fake target OS.
type Emulation struct {
	UnameOS   string            // uname -s (e.g. "Linux"); empty = real uname
	UnameArch string            // uname -m (e.g. "x86_64"); defaults to x86_64
	Files     map[string]string // virtual read-only files by absolute path
}

// unameMiddleware intercepts `uname` and reports the emulated OS/arch.
func unameMiddleware(e Emulation) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if e.UnameOS == "" || len(args) == 0 || filepath.Base(args[0]) != "uname" {
				return next(ctx, args)
			}
			fmt.Fprintln(interp.HandlerCtx(ctx).Stdout, e.uname(args[1:]))
			return nil
		}
	}
}

// virtualOpenMiddleware serves emulated files to redirections and `cat`-style
// builtin reads.
func virtualOpenMiddleware(e Emulation) OpenMiddleware {
	return func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc {
		return func(ctx context.Context, name string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if content, ok := e.Files[path.Clean(name)]; ok {
				return roFile{strings.NewReader(content)}, nil
			}
			return next(ctx, name, flag, perm)
		}
	}
}

// virtualStatHandler makes emulated files appear to exist (so `[ -r /etc/os-release ]`
// and similar tests pass) before falling back to the real filesystem.
func virtualStatHandler(e Emulation) interp.StatHandlerFunc {
	def := interp.DefaultStatHandler()
	return func(ctx context.Context, name string, follow bool) (fs.FileInfo, error) {
		if content, ok := e.Files[path.Clean(name)]; ok {
			return virtualFileInfo{name: path.Base(name), size: int64(len(content))}, nil
		}
		return def(ctx, name, follow)
	}
}

// virtualAccessHandler grants read access to emulated files, so the `-r` test
// (which uses access(2), bypassing StatHandler) passes for e.g. /etc/os-release.
func virtualAccessHandler(e Emulation) interp.AccessHandlerFunc {
	def := interp.DefaultAccessHandler()
	return func(ctx context.Context, name string, mode interp.AccessMode) error {
		if _, ok := e.Files[path.Clean(name)]; ok && mode&interp.AccessWrite == 0 {
			return nil // readable/executable-ok; never writable
		}
		return def(ctx, name, mode)
	}
}

// roFile adapts a string into a read-only file for the OpenHandler.
type roFile struct{ *strings.Reader }

func (roFile) Write([]byte) (int, error) { return 0, fmt.Errorf("read-only") }
func (roFile) Close() error              { return nil }

type virtualFileInfo struct {
	name string
	size int64
}

func (f virtualFileInfo) Name() string       { return f.name }
func (f virtualFileInfo) Size() int64        { return f.size }
func (f virtualFileInfo) Mode() fs.FileMode  { return 0o444 }
func (f virtualFileInfo) ModTime() time.Time { return time.Unix(0, 0) }
func (f virtualFileInfo) IsDir() bool        { return false }
func (f virtualFileInfo) Sys() any           { return nil }

// uname renders the emulated `uname` output for the given flags.
func (e Emulation) uname(flags []string) string {
	arch := e.UnameArch
	if arch == "" {
		arch = "x86_64"
	}
	var parts []string
	sawFlag := false
	for _, f := range flags {
		for _, c := range strings.TrimPrefix(f, "-") {
			sawFlag = true
			switch c {
			case 's':
				parts = append(parts, e.UnameOS)
			case 'm', 'p', 'i':
				parts = append(parts, arch)
			case 'r':
				parts = append(parts, "6.0.0-sandbox")
			case 'o':
				parts = append(parts, "GNU/Linux")
			case 'n':
				parts = append(parts, "sandbox")
			case 'a':
				return e.UnameOS + " sandbox 6.0.0-sandbox #1 SMP " + arch + " GNU/Linux"
			}
		}
	}
	if !sawFlag {
		return e.UnameOS // bare `uname` → kernel name
	}
	return strings.Join(parts, " ")
}

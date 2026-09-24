//go:build unix

package sandbox

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/shell"
)

// controllingTTYMiddleware marks commands whose stdout is the script terminal.
// The default executor uses that mark to create a session and make tty the
// child's controlling terminal. Restricting this to the terminal-facing member
// of a pipeline avoids several concurrent sessions trying to acquire one PTY.
func controllingTTYMiddleware(tty *os.File) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if !shell.SameOpenFile(interp.HandlerCtx(ctx).Stdout, tty) {
				return next(ctx, args)
			}
			err := next(interp.WithControllingTTY(ctx, tty), args)
			return errors.Join(err, shell.RestoreTTY(tty))
		}
	}
}

// controllingTTYOpenMiddleware makes shell-level redirections such as
// `gcloud setup </dev/tty` use the script PTY instead of tview's physical TTY.
func controllingTTYOpenMiddleware(tty *os.File) OpenMiddleware {
	return func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc {
		return func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if filepath.Clean(path) != "/dev/tty" {
				return next(ctx, path, flag, perm)
			}
			fd, err := unix.Dup(int(tty.Fd()))
			if err != nil {
				return nil, err
			}
			return os.NewFile(uintptr(fd), tty.Name()), nil
		}
	}
}

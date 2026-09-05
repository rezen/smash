//go:build unix

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"mvdan.cc/sh/v3/interp"
)

// controllingTTYMiddleware marks commands whose stdout is the script terminal.
// The default executor uses that mark to create a session and make tty the
// child's controlling terminal. Restricting this to the terminal-facing member
// of a pipeline avoids several concurrent sessions trying to acquire one PTY.
func controllingTTYMiddleware(tty *os.File) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if !sameOpenFile(interp.HandlerCtx(ctx).Stdout, tty) {
				return next(ctx, args)
			}
			err := next(interp.WithControllingTTY(ctx, tty), args)
			return errors.Join(err, restoreTTY(tty))
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

func sameOpenFile(w io.Writer, tty *os.File) bool {
	f, ok := w.(*os.File)
	if !ok || f == nil || tty == nil {
		return false
	}
	if f == tty {
		return true
	}
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := tty.Stat()
	return err == nil && os.SameFile(a, b)
}

// restoreTTY reopens the slave into the original descriptor number. Darwin
// revokes that descriptor when a controlling-terminal session leader exits;
// keeping its number stable means the interpreter and later commands can keep
// using the *os.File already stored in Config.
func restoreTTY(tty *os.File) error {
	fd, err := unix.Open(tty.Name(), unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fmt.Errorf("reopening script terminal: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Dup2(fd, int(tty.Fd())); err != nil {
		return fmt.Errorf("restoring script terminal: %w", err)
	}
	return nil
}

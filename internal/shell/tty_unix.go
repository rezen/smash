//go:build unix

package shell

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// RestoreTTY reopens tty's device into the original descriptor number.
// Darwin revokes that descriptor when a controlling-terminal session leader
// exits; keeping its number stable means callers can keep using the
// *os.File they already hold.
func RestoreTTY(tty *os.File) error {
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

package sandbox

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// unwrapMiddleware rewrites a wrapped invocation (`sudo -E sh -c …`, `env X=1
// curl …`, `find … -exec rm {} ;`) to its inner command so every downstream
// exec handler enforces on the real command. See command.Unwrap.
func unwrapMiddleware(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		chain, inner := command.Unwrap(args)
		if len(chain) == 0 {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintf(hc.Stderr, "[sandbox] unwrapped %s → %s\n", strings.Join(chain, "+"), inner[0])
		return next(withWrappers(ctx, chain), inner)
	}
}

// The wrappers a command was reached through travel on the context so the
// audit record can name them. Enforcement deliberately forgets them — a guard
// must see the real command and nothing else — but the log must not: `sudo rm
// -rf /` and `rm -rf /` are the same command to the gate and very different
// events to whoever reads the trail afterwards.
type wrapperKey struct{}

func withWrappers(ctx context.Context, chain []string) context.Context {
	return context.WithValue(ctx, wrapperKey{}, chain)
}

// wrappersFrom returns the wrapper chain recorded for this command, outermost
// first, or nil when it was invoked directly.
func wrappersFrom(ctx context.Context) []string {
	chain, _ := ctx.Value(wrapperKey{}).([]string)
	return chain
}

// sudoGrantMiddleware answers a sudo/doas credential probe — an invocation
// with no inner command, which unwrapMiddleware leaves as `sudo` (`sudo -v`,
// `sudo -n -l mkdir`, `sudo -K`) — with silent success, as passwordless sudo
// would. It never runs sudo: a `sudo CMD` was already unwrapped to CMD, which
// runs confined. Installed by Config.AllowSudo.
func sudoGrantMiddleware(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 || !sudoNames[filepath.Base(args[0])] {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		fmt.Fprintf(hc.Stderr, "[sandbox] granted %s\n", strings.Join(args, " "))
		return nil
	}
}

var sudoNames = command.NewSet("sudo", "doas")

// sleepCapMiddleware caps `sleep` so a script can't burn real wall-time.
func sleepCapMiddleware(maxCap time.Duration) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) < 2 || filepath.Base(args[0]) != "sleep" {
				return next(ctx, args)
			}
			d, ok := parseSleep(args[1])
			if !ok || d <= maxCap {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			fmt.Fprintf(hc.Stderr, "[sandbox] capped sleep %s → %s\n", args[1], maxCap)
			select {
			case <-time.After(maxCap):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

// parseSleep parses a sleep argument like "20", "20s", "1m", "0.5".
func parseSleep(s string) (time.Duration, bool) {
	mult := time.Second
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 's':
			s = s[:n-1]
		case 'm':
			s, mult = s[:n-1], time.Minute
		case 'h':
			s, mult = s[:n-1], time.Hour
		case 'd':
			s, mult = s[:n-1], 24*time.Hour
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0, false
	}
	return time.Duration(f * float64(mult)), true
}

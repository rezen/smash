package sandbox

// `sh -c 'SCRIPT'` (and `bash -c`) is the universal escape hatch: an allowed
// shell runs an arbitrary string as a real OS process, and everything inside it
// runs OUTSIDE the sandbox. get-docker funnels its whole install through
// `sudo -E sh -c '…'`. Rather than execute a real shell, we parse the -c string
// and run it in a fresh sub-runner built from the SAME Config, so every command
// inside is enforced by the full handler stack again. Nesting depth is capped,
// and the run's timeout backstops any fork-bomb of nested `sh -c`.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

const maxShDepth = 32

func shInterpMiddleware(cfg Config) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			sr, ok := command.Lookup(args[0]).(command.ScriptRunner)
			if !ok {
				return next(ctx, args)
			}
			script, params, ok := sr.DashC(args)
			if !ok {
				return next(ctx, args) // e.g. `sh file.sh` — let the allow-list decide
			}
			posix := filepath.Base(args[0]) == "sh" // `sh -c` is POSIX mode; `bash -c` is not
			return interpret(ctx, cfg, interp.HandlerCtx(ctx), "sh -c", script, params, posix, oneLine(script))
		}
	}
}

// interpret runs src in a fresh sub-runner built from the same Config, so
// every command inside is re-enforced by the whole handler stack. name labels
// parse errors, params become $1…, and what is the interpreter's says so on
// stderr.
func interpret(ctx context.Context, cfg Config, hc interp.HandlerContext,
	name, src string, params []string, posix bool, note string,
) error {
	if cfg.depth >= maxShDepth {
		return failf(hc.Stderr, 1, "[sandbox] shell nesting too deep (%d)", cfg.depth)
	}
	prog, err := parseBash(name, src)
	if err != nil {
		return failf(hc.Stderr, 2, "%s: %v", name, err)
	}
	fmt.Fprintf(hc.Stderr, "[sandbox] %s → interpreting confined: %s\n", name, note)

	sub := cfg
	sub.Dir = hc.Dir
	sub.Env = hc.Env
	sub.Stdin = hc.Stdin
	sub.Stdout = hc.Stdout
	sub.Stderr = hc.Stderr
	sub.Args = params
	sub.Posix = posix
	sub.depth = cfg.depth + 1
	runner, err := buildRunner(sub)
	if err != nil {
		return err
	}
	return runner.Run(ctx, prog)
}

// scriptRunner interprets a shell script confined, the way `sh -c` is. The
// command gate holds one so that an in-root script — which the kernel would
// hand to a real shell — is re-enforced instead of trusted; see runFromRoot.
type scriptRunner func(ctx context.Context, hc interp.HandlerContext, path string, args []string, posix bool) error

// confinedScriptRunner builds the gate's scriptRunner from the same Config the
// rest of the stack uses, so a script's contents face every guard again.
func confinedScriptRunner(cfg Config) scriptRunner {
	return func(ctx context.Context, hc interp.HandlerContext, path string, args []string, posix bool) error {
		src, err := os.ReadFile(path)
		if err != nil {
			return failf(hc.Stderr, 126, "%s: %v", path, err)
		}
		return interpret(ctx, cfg, hc, path, string(src), args, posix, path)
	}
}

// oneLine collapses a script to a single truncated line for logging.
func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

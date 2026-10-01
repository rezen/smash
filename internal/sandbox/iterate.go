package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

const maxIterationBytes = 1 << 20

type iterationDriverKey struct{}

func iterateMiddleware(cfg Config) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			p := parsedFrom(ctx, args)
			iter, ok := p.Command().(command.Iterator)
			if !ok {
				return next(ctx, args)
			}
			plan, valid := iter.Plan(p)
			if !valid {
				if p.Name == "find" && hasFindAction(args) {
					return failf(interp.HandlerCtx(ctx).Stderr, 1, "find: unsupported action combination")
				}
				if p.Name == "xargs" {
					return failf(interp.HandlerCtx(ctx).Stderr, 1, "xargs: unsupported options")
				}
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			var data []byte
			if len(plan.Driver) > 0 {
				out := &limitedIterationWriter{}
				err := runIterationChild(context.WithValue(ctx, iterationDriverKey{}, true), cfg, hc, plan.Driver, hc.Dir, out, nil)
				if err != nil {
					return err
				}
				data = out.Bytes()
			} else {
				r := hc.Stdin
				if plan.ArgFile != "" {
					path := plan.ArgFile
					if !filepath.IsAbs(path) {
						path = filepath.Join(hc.Dir, path)
					}
					f, err := os.Open(path)
					if err != nil {
						return failf(hc.Stderr, 1, "xargs: %v", err)
					}
					b, err := io.ReadAll(io.LimitReader(f, maxIterationBytes+1))
					f.Close()
					if err != nil {
						return failf(hc.Stderr, 1, "xargs: %v", err)
					}
					data = b
				} else if r != nil {
					b, err := io.ReadAll(io.LimitReader(r, maxIterationBytes+1))
					if err != nil {
						return failf(hc.Stderr, 1, "xargs: %v", err)
					}
					data = b
				}
			}
			if len(data) > maxIterationBytes {
				return failf(hc.Stderr, 1, "%s: input too large", p.Name)
			}
			items, splitErr := splitIterationItems(data, plan)
			if splitErr != nil {
				return failf(hc.Stderr, 1, "xargs: %v", splitErr)
			}
			if len(items) == 0 && !plan.RunEmpty {
				return nil
			}
			batch := plan.Batch
			if batch <= 0 {
				batch = len(items)
				if batch == 0 {
					batch = 1
				}
			}
			failed := false
			for start := 0; start < len(items) || start == 0 && len(items) == 0; start += batch {
				end := start + batch
				if end > len(items) {
					end = len(items)
				}
				var group []string
				if start < len(items) {
					group = items[start:end]
				}
				argv, dir := iterationArgv(plan, group, hc.Dir)
				if plan.Trace {
					fmt.Fprintln(hc.Stderr, command.JoinArgs(argv))
				}
				if err := runIterationChild(withWrappers(ctx, append(append([]string(nil), wrappersFrom(ctx)...), p.Name)), cfg, hc, argv, dir, hc.Stdout, nil); err != nil {
					if code, ok := exitCode(err); ok && code == 255 {
						return interp.ExitStatus(124)
					}
					if _, ok := exitCode(err); !ok {
						return interp.ExitStatus(125)
					}
					failed = true
				}
				if end == len(items) {
					break
				}
			}
			if failed {
				return interp.ExitStatus(123)
			}
			return nil
		}
	}
}

type limitedIterationWriter struct{ bytes.Buffer }

func (w *limitedIterationWriter) Write(p []byte) (int, error) {
	if w.Len()+len(p) > maxIterationBytes {
		return 0, fmt.Errorf("iteration output too large")
	}
	return w.Buffer.Write(p)
}

func hasFindAction(args []string) bool {
	for _, a := range args {
		switch a {
		case "-exec", "-execdir", "-ok", "-okdir":
			return true
		}
	}
	return false
}

func splitIterationItems(data []byte, p command.Iteration) ([]string, error) {
	if p.NUL || p.Delimiter != "" {
		sep := byte(0)
		if p.Delimiter != "" {
			sep = p.Delimiter[0]
		}
		var items []string
		for _, b := range bytes.Split(data, []byte{sep}) {
			if len(b) > 0 {
				items = append(items, string(b))
			}
		}
		return items, nil
	}
	var items []string
	var word strings.Builder
	quote := rune(0)
	escape, active := false, false
	flush := func() {
		if active {
			items = append(items, word.String())
			word.Reset()
			active = false
		}
	}
	for _, r := range string(data) {
		switch {
		case escape:
			word.WriteRune(r)
			escape, active = false, true
		case r == '\\' && quote != '\'':
			escape = true
			active = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				word.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, active = r, true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			word.WriteRune(r)
			active = true
		}
	}
	if quote != 0 || escape {
		return nil, fmt.Errorf("unmatched quote or escape")
	}
	flush()
	return items, nil
}

func iterationArgv(p command.Iteration, items []string, dir string) ([]string, string) {
	out := append([]string(nil), p.Template...)
	if p.Dir && len(items) > 0 {
		itemDir := filepath.Dir(items[0])
		if filepath.IsAbs(itemDir) {
			dir = itemDir
		} else {
			dir = filepath.Join(dir, itemDir)
		}
		for i, item := range items {
			items[i] = "./" + filepath.Base(item)
		}
	}
	if p.Placeholder == "" {
		return append(out, items...), dir
	}
	var expanded []string
	for _, a := range out {
		if a == p.Placeholder {
			expanded = append(expanded, items...)
		} else if strings.Contains(a, p.Placeholder) {
			expanded = append(expanded, strings.ReplaceAll(a, p.Placeholder, strings.Join(items, " ")))
		} else {
			expanded = append(expanded, a)
		}
	}
	return expanded, dir
}

func runIterationChild(ctx context.Context, cfg Config, hc interp.HandlerContext, args []string, dir string, stdout io.Writer, stdin io.Reader) error {
	if depthFrom(ctx) >= maxShDepth {
		return failf(hc.Stderr, 1, "[sandbox] shell nesting too deep (%d)", depthFrom(ctx))
	}
	prog, err := parseBash("iteration", command.JoinArgs(args))
	if err != nil {
		return failf(hc.Stderr, 2, "iteration: %v", err)
	}
	sub := cfg
	if stdin == nil {
		stdin = bytes.NewReader(nil)
	}
	sub.Dir, sub.Env, sub.Stdin, sub.Stdout, sub.Stderr = dir, hc.Env, stdin, stdout, hc.Stderr
	sub.Args = nil
	runner, err := buildRunner(sub)
	if err != nil {
		return err
	}
	return runner.Run(withDepth(ctx, depthFrom(ctx)+1), prog)
}

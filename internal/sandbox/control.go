package sandbox

// Control: disable commands outright, and mock any command's stdout, stderr
// and exit code by matcher. Both act on the REAL command, after wrappers are
// unwrapped, so `sudo rm`, `find -exec rm` and `sh -c 'rm …'` are all caught.
// Denial is checked before mocks — a disabled command cannot be mocked back
// to life — and both run before the network layer and the allow-list, so a
// mocked curl never touches the network.

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// Disable blocks the named commands regardless of the allow-list.
func (cfg *Config) Disable(names ...string) { cfg.Denied = cfg.Denied.With(names...) }

func denyMiddleware(denied command.Set) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) > 0 && denied[path.Base(args[0])] {
				return failf(interp.HandlerCtx(ctx).Stderr, 126, "[sandbox] disabled command: %s", args[0])
			}
			return next(ctx, args)
		}
	}
}

// Matcher decides whether a Mock applies to an invocation.
type Matcher func(p command.ParsedCommand) bool

// MatchName matches by command name (any of names; paths are reduced to their base).
func MatchName(names ...string) Matcher {
	set := command.NewSet(names...)
	return func(p command.ParsedCommand) bool { return set[p.Name] }
}

// MatchArgs matches the exact argv (name and arguments).
func MatchArgs(args ...string) Matcher {
	return func(p command.ParsedCommand) bool { return sameArgv(p.Argv(), args) && len(p.Argv()) == len(args) }
}

// MatchPrefix matches an argv that starts with args.
func MatchPrefix(args ...string) Matcher {
	return func(p command.ParsedCommand) bool {
		return len(p.Argv()) >= len(args) && sameArgv(p.Argv()[:len(args)], args)
	}
}

func sameArgv(argv, want []string) bool {
	if len(argv) < len(want) {
		return false
	}
	for i, w := range want {
		a := argv[i]
		if i == 0 {
			a = path.Base(a)
		}
		if a != w {
			return false
		}
	}
	return true
}

// MatchGlob matches a pattern against the space-joined argv, e.g.
// "curl * https://releases.astral.sh/*" or "uname -m". Unlike path globs,
// "*" matches anything including "/" and spaces; "?" matches one character.
func MatchGlob(pattern string) Matcher {
	re := globRE(pattern)
	return func(p command.ParsedCommand) bool {
		argv := append([]string{p.Name}, p.Argv()[1:]...)
		return re.MatchString(strings.Join(argv, " "))
	}
}

// MatchResource matches an invocation touching a resource of kind whose value
// matches the glob, e.g. MatchResource("url", "https://github.com/superfly/*").
func MatchResource(kind, valueGlob string) Matcher {
	re := globRE(valueGlob)
	return func(p command.ParsedCommand) bool {
		for _, r := range p.Resources() {
			if r.Kind == kind && re.MatchString(r.Value) {
				return true
			}
		}
		return false
	}
}

// globRE compiles a "*"/"?" glob into an anchored regexp.
func globRE(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// MatchFunc adapts any predicate over the parsed command (typed params
// included: p.TypedParams().(command.CurlParams).Follow, …).
func MatchFunc(f func(p command.ParsedCommand) bool) Matcher { return f }

// And requires every matcher; Or accepts any.
func (m Matcher) And(others ...Matcher) Matcher {
	return func(p command.ParsedCommand) bool {
		if !m(p) {
			return false
		}
		for _, o := range others {
			if !o(p) {
				return false
			}
		}
		return true
	}
}

func (m Matcher) Or(others ...Matcher) Matcher {
	return func(p command.ParsedCommand) bool {
		if m(p) {
			return true
		}
		for _, o := range others {
			if o(p) {
				return true
			}
		}
		return false
	}
}

// Mock replaces matching invocations with a canned (or computed) response.
type Mock struct {
	Match  Matcher
	Stdout string
	Stderr string
	Exit   int
	// Respond, when set, computes the response per invocation and overrides
	// the static fields.
	Respond func(p command.ParsedCommand) (stdout, stderr string, exit int)

	mu    sync.Mutex
	calls []command.ParsedCommand
}

// Calls returns every invocation this mock answered, in order.
func (m *Mock) Calls() []command.ParsedCommand {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]command.ParsedCommand(nil), m.calls...)
}

// Called reports how many invocations this mock answered.
func (m *Mock) Called() int { return len(m.Calls()) }

// Mock registers a canned response for invocations matched by match and
// returns the Mock so a test can inspect its Calls.
func (cfg *Config) Mock(match Matcher, stdout, stderr string, exit int) *Mock {
	m := &Mock{Match: match, Stdout: stdout, Stderr: stderr, Exit: exit}
	cfg.Mocks = append(cfg.Mocks, m)
	return m
}

// MockFunc registers a dynamic mock.
func (cfg *Config) MockFunc(match Matcher, respond func(p command.ParsedCommand) (stdout, stderr string, exit int)) *Mock {
	m := &Mock{Match: match, Respond: respond}
	cfg.Mocks = append(cfg.Mocks, m)
	return m
}

func mockMiddleware(mocks []*Mock) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			p := command.Parse(args)
			for _, m := range mocks {
				if m.Match == nil || !m.Match(p) {
					continue
				}
				m.mu.Lock()
				m.calls = append(m.calls, p)
				m.mu.Unlock()
				out, errOut, exit := m.Stdout, m.Stderr, m.Exit
				if m.Respond != nil {
					out, errOut, exit = m.Respond(p)
				}
				hc := interp.HandlerCtx(ctx)
				if out != "" {
					fmt.Fprint(hc.Stdout, out)
				}
				if errOut != "" {
					fmt.Fprint(hc.Stderr, errOut)
				}
				if exit != 0 {
					return interp.ExitStatus(exit)
				}
				return nil
			}
			return next(ctx, args)
		}
	}
}

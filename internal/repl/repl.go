// Package repl reads shell input without reading ahead into commands' stdin.
package repl

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/rezen/smash/internal/sandbox"
	"github.com/rezen/smash/internal/shell"
	"golang.org/x/term"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

type Options struct {
	Session              *sandbox.Session
	Stdin                io.Reader
	Stdout, Stderr       io.Writer
	Prompt, Continuation string
	Interrupts           <-chan os.Signal
}

var errInterrupted = errors.New("input interrupted")
var errClosed = errors.New("interrupt channel closed")

type readResult struct {
	data []byte
	err  error
}

// lineSource has at most one outstanding read. An interrupted read remains
// outstanding and supplies the next request; no worker reads during execution.
// A caller owns Stdin and can close it to release a read after cancellation.
type lineSource struct {
	ctx        context.Context
	input      io.Reader
	terminal   bool
	interrupts <-chan os.Signal
	pending    chan readResult
	rest       []byte
	end        error
}

func (s *lineSource) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.rest) > 0 {
		n := copy(p, s.rest)
		s.rest = s.rest[n:]
		return n, nil
	}
	if s.end != nil {
		return 0, s.end
	}
	if s.pending == nil {
		ch := make(chan readResult, 1)
		s.pending = ch
		go func() {
			if s.terminal {
				b := make([]byte, 4096)
				n, err := s.input.Read(b)
				ch <- readResult{b[:n], err}
				return
			}
			b := make([]byte, 0, 128)
			one := make([]byte, 1)
			for len(b) < 4096 {
				n, err := s.input.Read(one)
				if n > 0 {
					b = append(b, one[0])
				}
				if err != nil || (n > 0 && one[0] == '\n') {
					if err == io.EOF && len(b) > 0 && b[len(b)-1] != '\n' {
						b = append(b, '\n')
					}
					ch <- readResult{b, err}
					return
				}
			}
			ch <- readResult{data: b}
		}()
	}
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case _, ok := <-s.interrupts:
		if !ok {
			return 0, errClosed
		}
		return 0, errInterrupted
	case r := <-s.pending:
		s.pending = nil
		s.rest = r.data
		s.end = r.err
		if len(s.rest) > 0 {
			n := copy(p, s.rest)
			s.rest = s.rest[n:]
			return n, nil
		}
		return 0, s.end
	}
}

// Run drives one persistent session. Non-terminal input never gets prompts.
func Run(ctx context.Context, o Options) (int, error) {
	if o.Session == nil || o.Stdin == nil {
		return 1, errors.New("repl needs a session and stdin")
	}
	if o.Stdout == nil {
		o.Stdout = io.Discard
	}
	if o.Stderr == nil {
		o.Stderr = io.Discard
	}
	if o.Prompt == "" {
		o.Prompt = "smash[block]$ "
	}
	if o.Continuation == "" {
		o.Continuation = "> "
	}
	var tty *os.File
	var state *term.State
	if f, ok := o.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		tty = f
		state, _ = term.GetState(int(f.Fd()))
	}
	prompt := func(s string) {
		if tty != nil {
			fmt.Fprint(o.Stdout, s)
		}
	}
	source := &lineSource{ctx: ctx, input: o.Stdin, terminal: tty != nil, interrupts: o.Interrupts}
	status := 0
	for {
		parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
		restart := false
		prompt(o.Prompt)
		for stmts, err := range parser.InteractiveSeq(source) {
			if err != nil {
				switch {
				case errors.Is(err, errClosed):
					return 130, nil
				case errors.Is(err, ctx.Err()):
					return 130, ctx.Err()
				case errors.Is(err, errInterrupted):
					status = 130
					fmt.Fprintln(o.Stderr, "^C")
				default:
					status = 2
					fmt.Fprintf(o.Stderr, "smash: %v\n", err)
					if source.end != nil && !errors.Is(source.end, io.EOF) {
						return status, source.end
					}
				}
				restart = true
				break
			}
			if parser.Incomplete() {
				prompt(o.Continuation)
				continue
			}
			if len(stmts) > 0 {
				runCtx, cancel := context.WithCancel(ctx)
				done := make(chan error, 1)
				go func() { done <- o.Session.Run(runCtx, stmts) }()
				interrupted, closed := false, false
				interrupts := o.Interrupts
				var runErr error
			running:
				for {
					select {
					case runErr = <-done:
						break running
					case _, ok := <-interrupts:
						interrupted = true
						closed = !ok
						cancel()
						interrupts = nil
					case <-runCtx.Done():
						// Wait for child cleanup without spinning on a cancelled context.
						runErr = <-done
						break running
					}
				}
				cancel()
				if tty != nil {
					// Restore the descriptor if Darwin revoked it, then cooked-mode state.
					if err := shell.RestoreTTY(tty); err != nil {
						return 1, err
					}
					if state != nil {
						if err := term.Restore(int(tty.Fd()), state); err != nil {
							return 1, err
						}
					}
				}
				status = 0
				if runErr != nil {
					if code, ok := errors.AsType[interp.ExitStatus](runErr); ok {
						status = int(code)
					} else if !(interrupted && errors.Is(runErr, context.Canceled)) {
						status = 1
						fmt.Fprintf(o.Stderr, "smash: %v\n", runErr)
					}
				}
				if interrupted {
					status = 130
					// Ignore additional Ctrl-C notifications queued while the
					// cancelled command was shutting its child down.
					closed = drainSignals(o.Interrupts) || closed
				}
				if closed {
					return 130, nil
				}
				if ctx.Err() != nil {
					return 130, ctx.Err()
				}
				if o.Session.Exited() && !interrupted && !errors.Is(runErr, context.DeadlineExceeded) && !errors.Is(runErr, context.Canceled) {
					return status, nil
				}
			}
			prompt(o.Prompt)
		}
		if !restart {
			return status, nil
		}
	}
}

// drainSignals discards pending interrupts and reports a closed channel.
func drainSignals(ch <-chan os.Signal) bool {
	if ch == nil {
		return false
	}
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
		default:
			return false
		}
	}
}

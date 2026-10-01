package approve

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/rezen/smash/internal/sandbox"
)

// Prompt uses a dedicated terminal stream, never the shell's stdin. A cancelled
// read retains the serialization token until it completes, so its stale answer
// cannot approve the next command. Closing the owned tty releases that read.
type Prompt struct {
	input  io.Reader
	output io.Writer
	once   sync.Once
	token  chan struct{}
}

func NewPrompt(r io.Reader, w io.Writer) *Prompt { return &Prompt{input: r, output: w} }
func (p *Prompt) Approve(ctx context.Context, req sandbox.ApprovalRequest) (sandbox.Decision, error) {
	p.once.Do(func() { p.token = make(chan struct{}, 1); p.token <- struct{}{} })
	select {
	case <-ctx.Done():
		return sandbox.Decision{}, ctx.Err()
	case <-p.token:
	}
	if err := ctx.Err(); err != nil {
		p.token <- struct{}{}
		return sandbox.Decision{}, err
	}
	fmt.Fprintf(p.output, "[smash] run: %s  (%s by policy) [y/N/a] ", sandbox.TerminalText(req.Line), req.Verdict)
	result := make(chan struct {
		line string
		err  error
	}, 1)
	go func() {
		var b strings.Builder
		one := make([]byte, 1)
		var err error
		for {
			var n int
			n, err = p.input.Read(one)
			if n > 0 {
				if one[0] == '\n' {
					break
				}
				b.WriteByte(one[0])
			}
			if err != nil {
				break
			}
		}
		result <- struct {
			line string
			err  error
		}{b.String(), err}
		p.token <- struct{}{}
	}()
	select {
	case <-ctx.Done():
		return sandbox.Decision{}, ctx.Err()
	case r := <-result:
		if r.err != nil {
			return sandbox.Decision{}, r.err
		}
		switch strings.ToLower(strings.TrimSpace(r.line)) {
		case "y":
			return sandbox.Decision{Allow: true}, nil
		case "a":
			return sandbox.Decision{Allow: true, Remember: sandbox.RememberName}, nil
		default:
			return sandbox.Decision{Reason: "declined at terminal"}, nil
		}
	}
}

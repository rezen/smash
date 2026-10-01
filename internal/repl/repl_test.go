package repl

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rezen/smash/internal/sandbox"
	"mvdan.cc/sh/v3/expand"
)

type buffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *buffer) Write(p []byte) (int, error) { b.mu.Lock(); defer b.mu.Unlock(); return b.b.Write(p) }
func (b *buffer) String() string              { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }
func options(t *testing.T, r io.Reader) (Options, *buffer, *buffer) {
	t.Helper()
	root := t.TempDir()
	out, errout := &buffer{}, &buffer{}
	cfg := sandbox.NewConfig(root, root, expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Timeout = 0
	cfg.Interactive = true
	cfg.Stdin = r
	cfg.Stdout = out
	cfg.Stderr = errout
	s, err := sandbox.NewSession(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return Options{Session: s, Stdin: r, Stdout: out, Stderr: errout}, out, errout
}
func TestREPLInput(t *testing.T) {
	for _, tt := range []struct {
		name, input, out, diagnostic string
		code                         int
	}{
		{"continuation", "if true; then\necho y\nfi\n", "y\n", "", 0},
		{"leading whitespace", "  echo trimmed\n", "trimmed\n", "", 0},
		{"shared stdin", "read x\nhello\necho got:$x\n", "got:hello\n", "", 0},
		{"parse recovery", "echo )\necho survived\n", "survived\n", "smash:", 0},
		{"exit", "exit 7\necho unreachable\n", "", "", 7},
		{"last status", "false\n", "", "", 1},
		{"no final newline", "echo tail", "tail\n", "", 0},
		{"blank retains status", "false\n\n", "", "", 1},
		{"incomplete eof", "if true; then\n", "", "smash:", 2},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatal(pipeErr)
			}
			defer r.Close()
			io.WriteString(w, tt.input)
			w.Close()
			o, out, er := options(t, r)
			code, err := Run(context.Background(), o)
			if err != nil || code != tt.code || out.String() != tt.out || !strings.Contains(er.String(), tt.diagnostic) {
				t.Fatalf("code=%d err=%v out=%q stderr=%q", code, err, out.String(), er.String())
			}
		})
	}
}

// afterInput signals when the parser requests the line following a known prefix.
type afterInput struct {
	io.Reader
	remaining int
	ready     chan struct{}
	once      sync.Once
}

func (r *afterInput) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		r.once.Do(func() { close(r.ready) })
	}
	n, err := r.Reader.Read(p)
	r.remaining -= n
	return n, err
}

func TestREPLInterrupt(t *testing.T) {
	for _, during := range []bool{false, true} {
		t.Run(map[bool]string{true: "command", false: "prompt"}[during], func(t *testing.T) {
			r, w, pipeErr := os.Pipe()
			if pipeErr != nil {
				t.Fatal(pipeErr)
			}
			defer r.Close()
			defer w.Close()
			o, out, er := options(t, r)
			ready := make(chan struct{})
			if !during {
				o.Stdin = &afterInput{Reader: r, remaining: len("if true; then\n"), ready: ready}
			}
			signals := make(chan os.Signal, 4)
			o.Interrupts = signals
			finished := make(chan int, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			go func() { code, _ := Run(ctx, o); finished <- code }()
			if during {
				io.WriteString(w, "sleep 30\n")
				deadline := time.Now().Add(time.Second)
				for !strings.Contains(er.String(), "capped sleep") && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
			} else {
				io.WriteString(w, "if true; then\n")
				select {
				case <-ready:
				case <-ctx.Done():
					t.Fatal("parser never reached continuation")
				}
			}
			signals <- os.Interrupt
			// Wait for prompt cancellation before supplying a new statement.
			if !during {
				deadline := time.Now().Add(time.Second)
				for !strings.Contains(er.String(), "^C") && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
			}
			io.WriteString(w, "echo recovered\nexit 0\n")
			w.Close()
			select {
			case code := <-finished:
				if code != 0 || out.String() != "recovered\n" {
					t.Fatalf("code=%d out=%q err=%q", code, out.String(), er.String())
				}
				if during && strings.Count(er.String(), "^C\n") != 0 {
					t.Fatalf("second interrupt was not ignored: %q", er.String())
				}
			case <-ctx.Done():
				t.Fatal("REPL hung")
			}
		})
	}
}
func TestInterruptChannelClosed(t *testing.T) {
	r, w, pipeErr := os.Pipe()
	if pipeErr != nil {
		t.Fatal(pipeErr)
	}
	defer r.Close()
	defer w.Close()
	o, _, _ := options(t, r)
	ch := make(chan os.Signal)
	close(ch)
	o.Interrupts = ch
	code, err := Run(context.Background(), o)
	if code != 130 || err != nil {
		t.Fatalf("%d %v", code, err)
	}
}

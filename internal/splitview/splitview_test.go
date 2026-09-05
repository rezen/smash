package splitview

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/creack/pty/v2"
	"github.com/gdamore/tcell/v2"
	"github.com/hinshun/vt10x"
	"mvdan.cc/sh/v3/expand"

	"github.com/rezen/smash/internal/sandbox"
)

func TestEncodeKey(t *testing.T) {
	tests := []struct {
		name      string
		event     *tcell.EventKey
		appCursor bool
		want      []byte
	}{
		{"rune", tcell.NewEventKey(tcell.KeyRune, 'λ', tcell.ModNone), false, []byte("λ")},
		{"alt rune", tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModAlt), false, []byte("\x1bx")},
		{"enter", tcell.NewEventKey(tcell.KeyEnter, 0, tcell.ModNone), false, []byte("\r")},
		{"control", tcell.NewEventKey(tcell.KeyCtrlC, 0, tcell.ModCtrl), false, []byte{3}},
		{"up", tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone), false, []byte("\x1b[A")},
		{"application up", tcell.NewEventKey(tcell.KeyUp, 0, tcell.ModNone), true, []byte("\x1bOA")},
		{"delete", tcell.NewEventKey(tcell.KeyDelete, 0, tcell.ModNone), false, []byte("\x1b[3~")},
		{"f5", tcell.NewEventKey(tcell.KeyF5, 0, tcell.ModNone), false, []byte("\x1b[15~")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := encodeKey(test.event, test.appCursor); !slices.Equal(got, test.want) {
				t.Fatalf("encodeKey = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTerminalPaneDrawsVTState(t *testing.T) {
	emulator := vt10x.New(vt10x.WithSize(20, 4))
	if _, err := emulator.Write([]byte("hello \x1b[31mred\x1b[0m")); err != nil {
		t.Fatal(err)
	}
	var input bytes.Buffer
	pane := newTerminalPane(emulator, &input, nil)
	pane.SetRect(0, 0, 20, 4)

	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	screen.SetSize(20, 4)
	pane.Draw(screen)
	screen.Show()

	cells, _, _ := screen.GetContents()
	var got []rune
	for x := 0; x < len("hello red"); x++ {
		got = append(got, cells[x].Runes...)
	}
	if string(got) != "hello red" {
		t.Fatalf("drawn row = %q", got)
	}
	redFG, _, _ := cells[6].Style.Decompose()
	if redFG != tcell.PaletteColor(1) {
		t.Fatalf("red foreground mapped to %v", redFG)
	}
}

func TestTerminalPaneForwardsInput(t *testing.T) {
	emulator := vt10x.New()
	var input bytes.Buffer
	pane := newTerminalPane(emulator, &input, nil)
	pane.InputHandler()(tcell.NewEventKey(tcell.KeyRune, 'y', tcell.ModNone), nil)
	if input.String() != "y" {
		t.Fatalf("input = %q, want y", input.String())
	}
	pane.PasteHandler()("es\n", nil)
	if input.String() != "yes\n" {
		t.Fatalf("input after paste = %q, want yes\\n", input.String())
	}
}

func TestSplitViewInteractiveRun(t *testing.T) {
	master, slave, err := pty.Open()
	if err != nil {
		t.Skipf("PTY unavailable: %v", err)
	}
	view := newSplitView(master, slave)
	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(80, 24)
	view.app.SetScreen(screen)

	interaction := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		waitFor := func(text string) bool {
			for !strings.Contains(view.terminal.emulator.String(), text) {
				if time.Now().After(deadline) {
					return false
				}
				time.Sleep(time.Millisecond)
			}
			return true
		}
		typeText := func(text string) {
			for _, r := range text {
				screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
			}
			screen.InjectKey(tcell.KeyEnter, 0, tcell.ModNone)
		}
		if !waitFor("Name: ") {
			screen.InjectKey(tcell.KeyCtrlC, 0, tcell.ModCtrl)
			interaction <- context.DeadlineExceeded
			return
		}
		typeText("Ada")
		if !waitFor("Cloud choice: ") {
			screen.InjectKey(tcell.KeyCtrlC, 0, tcell.ModCtrl)
			interaction <- context.DeadlineExceeded
			return
		}
		typeText("2")
		for !view.finished.Load() {
			if time.Now().After(deadline) {
				screen.InjectKey(tcell.KeyCtrlC, 0, tcell.ModCtrl)
				interaction <- context.DeadlineExceeded
				return
			}
			time.Sleep(time.Millisecond)
		}
		screen.InjectKey(tcell.KeyRune, 'q', tcell.ModNone)
		interaction <- nil
	}()

	root := t.TempDir()
	cfg := sandbox.NewConfig(root, root, expand.ListEnviron("PATH=/usr/bin:/bin", "TERM=xterm-256color"))
	cfg.Stdin, cfg.Stdout, cfg.Stderr = view.Stdio()
	cfg.ControllingTTY = view.TTY()
	cfg.Auditor = sandbox.TextAuditor(view.EventWriter())
	err = view.Run(func(ctx context.Context) error {
		return sandbox.RunContext(ctx, cfg, "prompt.sh", fmt.Sprintf(`
if [ -t 0 ] && [ -t 1 ] && [ -t 2 ]; then echo "PTY: yes"; fi
printf 'Name: '
read -r name </dev/tty
printf 'Hello, %%s\n' "$name"
SMASH_TTY_HELPER=1 %q -test.run=^TestControllingTTYHelperProcess$
uname -s
`, os.Args[0]))
	})
	if interactErr := <-interaction; interactErr != nil {
		t.Fatalf("interaction timed out: %v", interactErr)
	}
	if err != nil {
		t.Fatalf("interactive run: %v\nterminal:\n%s\nevents:\n%s", err, view.terminal.emulator.String(), view.events.GetText(false))
	}
	scriptOutput := view.terminal.emulator.String()
	for _, want := range []string{"PTY: yes", "Hello, Ada", "Cloud chose 2"} {
		if !strings.Contains(scriptOutput, want) {
			t.Errorf("script terminal missing %q:\n%s", want, scriptOutput)
		}
	}
	if events := view.events.GetText(false); !strings.Contains(events, "name: uname") {
		t.Errorf("event pane missing uname audit record:\n%s", events)
	}
}

// TestControllingTTYHelperProcess is re-executed by TestSplitViewInteractiveRun
// as a real external program. Opening /dev/tty rather than reading stdin pins
// the behavior needed by interactive tools such as gcloud.
func TestControllingTTYHelperProcess(t *testing.T) {
	if os.Getenv("SMASH_TTY_HELPER") != "1" {
		return
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer tty.Close()
	if _, err := fmt.Fprint(tty, "Cloud choice: "); err != nil {
		os.Exit(2)
	}
	var choice string
	if _, err := fmt.Fscanln(tty, &choice); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Fprintf(tty, "Cloud chose %s\n", choice)
	os.Exit(0)
}

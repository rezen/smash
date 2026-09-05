package splitview

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty/v2"
	"github.com/gdamore/tcell/v2"
	"github.com/hinshun/vt10x"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

var ErrInterrupted = errors.New("interrupted")

// View is a tview application with a PTY-backed terminal in its upper
// pane and the Smash audit stream in its lower pane. The PTY is important: it
// lets installers see real terminal file descriptors, change echo settings,
// render ANSI control sequences, and use interactive prompts while tview owns
// the caller's physical terminal.
type View struct {
	app      *tview.Application
	terminal *terminalPane
	events   *tview.TextView
	status   *tview.TextView

	master *os.File
	slave  *os.File

	cancelMu sync.Mutex
	cancel   context.CancelFunc

	runComplete   atomic.Bool
	finished      atomic.Bool
	screenReady   atomic.Bool
	interrupted   atomic.Bool
	stopRequested atomic.Bool
	closeOnce     sync.Once
}

// Start prepares the TUI only for an interactive terminal using the
// default audit stream. Piped and redirected runs keep ordinary CLI streams.
func Start(stdin, stdout, stderr *os.File) (*View, bool, error) {
	if stdin == nil || stdout == nil || stderr == nil ||
		os.Getenv("TERM") == "" || os.Getenv("TERM") == "dumb" ||
		!term.IsTerminal(int(stdin.Fd())) ||
		!term.IsTerminal(int(stdout.Fd())) ||
		!term.IsTerminal(int(stderr.Fd())) {
		return nil, false, nil
	}
	width, height, err := term.GetSize(int(stdout.Fd()))
	if err != nil || width < 40 || height < 8 {
		return nil, false, nil
	}

	master, slave, err := pty.Open()
	if err != nil {
		return nil, false, fmt.Errorf("opening script terminal: %w", err)
	}
	physicalTTY, err := tcell.NewStdIoTty()
	if err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, false, nil
	}
	screen, err := tcell.NewTerminfoScreenFromTty(physicalTTY)
	if err != nil {
		_ = physicalTTY.Close()
		_ = master.Close()
		_ = slave.Close()
		return nil, false, nil
	}
	if err := screen.Init(); err != nil {
		_ = master.Close()
		_ = slave.Close()
		return nil, false, fmt.Errorf("starting terminal UI: %w", err)
	}
	view := newSplitView(master, slave)
	// Application.SetScreen initializes its argument but does not return that
	// error. The real screen is already initialized above; this wrapper makes
	// the second initialization a no-op so failures remain reportable.
	view.app.SetScreen(readyScreen{Screen: screen})
	view.screenReady.Store(true)
	return view, true, nil
}

type readyScreen struct{ tcell.Screen }

func (readyScreen) Init() error { return nil }

func newSplitView(master, slave *os.File) *View {
	app := tview.NewApplication().EnablePaste(true)
	emulator := vt10x.New(
		vt10x.WithWriter(master),
		vt10x.WithSize(80, 16),
	)
	scriptPane := newTerminalPane(emulator, master, func(cols, rows int) error {
		return pty.Setsize(master, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	})
	scriptPane.SetBorder(true).
		SetTitle(" Script terminal - stdout / stderr / input ").
		SetBorderColor(tcell.ColorSteelBlue).
		SetTitleColor(tcell.ColorLightSteelBlue)

	events := tview.NewTextView().
		SetScrollable(true).
		SetWrap(true).
		SetWordWrap(false).
		SetMaxLines(4000)
	events.SetBorder(true).
		SetTitle(" Smash events ").
		SetBorderColor(tcell.ColorDarkCyan).
		SetTitleColor(tcell.ColorLightCyan)
	events.ScrollToEnd()

	status := tview.NewTextView().
		SetTextAlign(tview.AlignCenter).
		SetText(" F6: switch panes   Ctrl-C: stop ")
	status.SetTextColor(tcell.ColorGray)

	layout := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(scriptPane, 0, 2, true).
		AddItem(events, 0, 1, false).
		AddItem(status, 1, 0, false)

	v := &View{
		app:      app,
		terminal: scriptPane,
		events:   events,
		status:   status,
		master:   master,
		slave:    slave,
	}
	events.SetChangedFunc(func() { app.Draw() })
	app.SetRoot(layout, true).SetFocus(scriptPane)
	app.SetInputCapture(v.captureKey)
	return v
}

func (v *View) Stdio() (io.Reader, io.Writer, io.Writer) {
	return v.slave, v.slave, v.slave
}

// TTY returns the script-side PTY. Callers pass it to the command runner so
// external interactive programs can use it as their controlling terminal.
func (v *View) TTY() *os.File { return v.slave }

func (v *View) EventWriter() io.Writer { return v.events }

// Run starts the physical-terminal UI and runs fn once the screen has been
// initialized. A completed run remains visible for inspection until Enter,
// Escape, or q is pressed.
func (v *View) Run(fn func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	v.cancelMu.Lock()
	v.cancel = cancel
	v.cancelMu.Unlock()
	defer func() {
		cancel()
		_ = v.Close()
	}()

	readDone := make(chan struct{})
	runResult := make(chan error, 1)
	var startOnce sync.Once
	started := false
	v.app.SetBeforeDrawFunc(func(tcell.Screen) bool {
		startOnce.Do(func() {
			started = true
			v.screenReady.Store(true)
			go v.readTerminal(readDone)
			go func() {
				err := fn(ctx)
				runResult <- err
				v.runComplete.Store(true)
				_ = v.slave.Close()
				<-readDone
				v.finished.Store(true)
				if v.stopRequested.Load() {
					v.app.Stop()
					return
				}
				v.app.QueueUpdateDraw(func() {
					if err == nil {
						v.status.SetText(" Run finished   F6: switch panes   Enter/Esc/q: close ")
						v.status.SetTextColor(tcell.ColorLightGreen)
					} else {
						v.status.SetText(fmt.Sprintf(" Run failed: %v   Enter/Esc/q: close ", err))
						v.status.SetTextColor(tcell.ColorLightCoral)
					}
				})
			}()
		})
		return false
	})

	appErr := v.app.Run()
	if !started {
		_ = v.master.Close()
		_ = v.slave.Close()
		return appErr
	}
	if !v.finished.Load() {
		v.stopRequested.Store(true)
		cancel()
	}
	runErr := <-runResult
	_ = v.master.Close()
	<-readDone
	if v.interrupted.Load() {
		return ErrInterrupted
	}
	return errors.Join(runErr, appErr)
}

func (v *View) readTerminal(done chan<- struct{}) {
	defer close(done)
	reader := bufio.NewReader(v.master)
	for {
		if err := v.terminal.emulator.Parse(reader); err != nil {
			// On Darwin, the PTY master can briefly report EIO when a session
			// leader exits and releases the slave as its controlling terminal.
			// The slave remains open for the next command, so retry until the
			// overall script has actually completed.
			if (errors.Is(err, syscall.EIO) || errors.Is(err, io.EOF)) && !v.runComplete.Load() {
				time.Sleep(time.Millisecond)
				continue
			}
			if !v.runComplete.Load() {
				v.stopRequested.Store(true)
				v.cancelRun(false)
				v.app.Stop()
			}
			return
		}
		v.app.Draw()
	}
}

func (v *View) captureKey(event *tcell.EventKey) *tcell.EventKey {
	if event.Key() == tcell.KeyF6 {
		if v.app.GetFocus() == v.terminal {
			v.app.SetFocus(v.events)
		} else {
			v.app.SetFocus(v.terminal)
		}
		return nil
	}
	if event.Key() == tcell.KeyCtrlC {
		v.stopRequested.Store(true)
		v.cancelRun(true)
		return nil
	}
	if v.finished.Load() && (event.Key() == tcell.KeyEnter || event.Key() == tcell.KeyCtrlJ ||
		event.Key() == tcell.KeyEscape ||
		event.Key() == tcell.KeyRune && (event.Rune() == 'q' || event.Rune() == 'Q')) {
		v.app.Stop()
		return nil
	}
	return event
}

func (v *View) cancelRun(interrupted bool) {
	if interrupted {
		v.interrupted.Store(true)
	}
	v.cancelMu.Lock()
	cancel := v.cancel
	v.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (v *View) Close() error {
	var closeErr error
	v.closeOnce.Do(func() {
		v.cancelRun(false)
		if v.screenReady.Load() {
			v.app.Stop()
		}
		closeErr = errors.Join(v.slave.Close(), v.master.Close())
	})
	return closeErr
}

// terminalPane renders vt10x's terminal state as a tview primitive and sends
// focused keyboard and paste input back to the PTY master.
type terminalPane struct {
	*tview.Box
	emulator vt10x.Terminal
	input    io.Writer
	resize   func(cols, rows int) error
	cols     int
	rows     int
}

func newTerminalPane(emulator vt10x.Terminal, input io.Writer, resize func(int, int) error) *terminalPane {
	return &terminalPane{
		Box:      tview.NewBox(),
		emulator: emulator,
		input:    input,
		resize:   resize,
	}
}

func (p *terminalPane) Draw(screen tcell.Screen) {
	p.Box.DrawForSubclass(screen, p)
	x, y, width, height := p.GetInnerRect()
	if width < 1 || height < 1 {
		return
	}
	if width != p.cols || height != p.rows {
		p.cols, p.rows = width, height
		p.emulator.Resize(width, height)
		if p.resize != nil {
			_ = p.resize(width, height)
		}
	}

	p.emulator.Lock()
	defer p.emulator.Unlock()
	cols, rows := p.emulator.Size()
	for row := 0; row < height && row < rows; row++ {
		for col := 0; col < width && col < cols; col++ {
			glyph := p.emulator.Cell(col, row)
			char := glyph.Char
			if char == 0 {
				char = ' '
			}
			screen.SetContent(x+col, y+row, char, nil, terminalStyle(glyph))
		}
	}
	if p.HasFocus() && p.emulator.CursorVisible() {
		cursor := p.emulator.Cursor()
		if cursor.X >= 0 && cursor.X < width && cursor.Y >= 0 && cursor.Y < height {
			screen.ShowCursor(x+cursor.X, y+cursor.Y)
		}
	}
}

func (p *terminalPane) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return p.WrapInputHandler(func(event *tcell.EventKey, _ func(tview.Primitive)) {
		p.emulator.Lock()
		appCursor := p.emulator.Mode()&vt10x.ModeAppCursor != 0
		p.emulator.Unlock()
		if data := encodeKey(event, appCursor); len(data) > 0 {
			_, _ = p.input.Write(data)
		}
	})
}

func (p *terminalPane) PasteHandler() func(string, func(tview.Primitive)) {
	return p.WrapPasteHandler(func(text string, _ func(tview.Primitive)) {
		_, _ = io.WriteString(p.input, text)
	})
}

func (p *terminalPane) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return p.WrapMouseHandler(func(_ tview.MouseAction, event *tcell.EventMouse, setFocus func(tview.Primitive)) (bool, tview.Primitive) {
		x, y := event.Position()
		if !p.InRect(x, y) {
			return false, nil
		}
		setFocus(p)
		return true, nil
	})
}

// vt10x's attribute bits are intentionally private, but Glyph.Mode exposes the
// bitset. These values are part of its stable parser representation.
const (
	vtAttrUnderline = 1 << 1
	vtAttrBold      = 1 << 2
	vtAttrItalic    = 1 << 4
	vtAttrBlink     = 1 << 5
)

func terminalStyle(glyph vt10x.Glyph) tcell.Style {
	style := tcell.StyleDefault.
		Foreground(terminalColor(glyph.FG)).
		Background(terminalColor(glyph.BG))
	return style.
		Underline(glyph.Mode&vtAttrUnderline != 0).
		Bold(glyph.Mode&vtAttrBold != 0).
		Italic(glyph.Mode&vtAttrItalic != 0).
		Blink(glyph.Mode&vtAttrBlink != 0)
}

func terminalColor(color vt10x.Color) tcell.Color {
	switch color {
	case vt10x.DefaultFG, vt10x.DefaultBG, vt10x.DefaultCursor:
		return tcell.ColorDefault
	}
	if color < 256 {
		return tcell.PaletteColor(int(color))
	}
	if color <= 0xffffff {
		return tcell.NewRGBColor(int32(color>>16), int32(color>>8&0xff), int32(color&0xff))
	}
	return tcell.ColorDefault
}

func encodeKey(event *tcell.EventKey, appCursor bool) []byte {
	key := event.Key()
	var value string
	switch {
	case key == tcell.KeyRune:
		r := event.Rune()
		if event.Modifiers()&tcell.ModCtrl != 0 {
			switch {
			case r >= 'a' && r <= 'z':
				value = string(byte(r-'a') + 1)
			case r >= 'A' && r <= 'Z':
				value = string(byte(r-'A') + 1)
			case r == ' ':
				value = "\x00"
			}
		} else {
			value = string(r)
		}
	case key >= tcell.KeyCtrlSpace && key <= tcell.KeyCtrlUnderscore:
		value = string(byte(key))
	case key == tcell.KeyBackspace2:
		value = "\x7f"
	case key == tcell.KeyUp:
		value = cursorSequence(appCursor, "A")
	case key == tcell.KeyDown:
		value = cursorSequence(appCursor, "B")
	case key == tcell.KeyRight:
		value = cursorSequence(appCursor, "C")
	case key == tcell.KeyLeft:
		value = cursorSequence(appCursor, "D")
	case key == tcell.KeyHome:
		value = "\x1b[H"
	case key == tcell.KeyEnd:
		value = "\x1b[F"
	case key == tcell.KeyInsert:
		value = "\x1b[2~"
	case key == tcell.KeyDelete:
		value = "\x1b[3~"
	case key == tcell.KeyPgUp:
		value = "\x1b[5~"
	case key == tcell.KeyPgDn:
		value = "\x1b[6~"
	case key == tcell.KeyBacktab:
		value = "\x1b[Z"
	case key >= tcell.KeyF1 && key <= tcell.KeyF4:
		value = "\x1bO" + string(rune('P'+key-tcell.KeyF1))
	case key >= tcell.KeyF5 && key <= tcell.KeyF12:
		codes := [...]string{"15", "17", "18", "19", "20", "21", "23", "24"}
		value = "\x1b[" + codes[key-tcell.KeyF5] + "~"
	}
	if value != "" && event.Modifiers()&tcell.ModAlt != 0 && !strings.HasPrefix(value, "\x1b") {
		value = "\x1b" + value
	}
	return []byte(value)
}

func cursorSequence(applicationMode bool, final string) string {
	if applicationMode {
		return "\x1bO" + final
	}
	return "\x1b[" + final
}

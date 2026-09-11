module github.com/rezen/smash

go 1.26.0

require (
	github.com/creack/pty/v2 v2.0.1
	github.com/gdamore/tcell/v2 v2.13.10
	github.com/hinshun/vt10x v0.0.0-20220301184237-5011da428d02
	github.com/rivo/tview v0.42.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	gopkg.in/yaml.v3 v3.0.1
	mvdan.cc/sh/v3 v3.14.0
)

require (
	github.com/gdamore/encoding v1.0.1 // indirect
	github.com/lucasb-eyer/go-colorful v1.3.0 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	golang.org/x/text v0.31.0 // indirect
)

replace mvdan.cc/sh/v3 => ./third_party/sh

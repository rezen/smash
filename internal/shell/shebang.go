package shell

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Interpreter parses a script's first line and returns the interpreter a
// `#!` names. ok is false when the line is not a shebang or names nothing.
// `#!/usr/bin/env python3` names python3 — env itself decides nothing, so
// env's flags (`-S`) and NAME=value assignments are skipped.
func Interpreter(line string) (string, bool) {
	rest, ok := strings.CutPrefix(line, "#!")
	if !ok {
		return "", false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	if filepath.Base(fields[0]) != "env" {
		return fields[0], true
	}
	for _, f := range fields[1:] {
		if !strings.HasPrefix(f, "-") && !strings.Contains(f, "=") {
			return f, true
		}
	}
	return "", false
}

// IsSh reports whether src's first line is a shebang for sh itself
// (`#!/bin/sh`, `#!/usr/bin/env sh`, …) as opposed to bash or no shebang.
func IsSh(src string) bool {
	line, _, _ := strings.Cut(src, "\n")
	interp, ok := Interpreter(line)
	return ok && filepath.Base(interp) == "sh"
}

// InterpreterFromFile returns the interpreter a file's `#!` line names. ok
// is false for a binary, an unreadable file, or a script with no shebang
// (which the kernel refuses and the shell would run itself).
func InterpreterFromFile(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := io.ReadFull(f, buf)
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	return Interpreter(line)
}

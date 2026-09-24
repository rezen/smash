package shell

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInterpreter(t *testing.T) {
	cases := []struct {
		line, want string
		ok         bool
	}{
		{"#!/bin/sh", "/bin/sh", true},
		{"#!/bin/bash -eu", "/bin/bash", true},
		{"#!/usr/bin/env sh", "sh", true},
		{"#!/usr/bin/env python3", "python3", true},
		{"#!/usr/bin/env -S sh -eu", "sh", true},
		{"#!/usr/bin/env FOO=bar sh", "sh", true},
		{"#! /bin/sh", "/bin/sh", true},
		{"#!/usr/bin/env", "", false},
		{"#!", "", false},
		{"echo hi", "", false},
	}
	for _, c := range cases {
		got, ok := Interpreter(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("Interpreter(%q) = %q, %v; want %q, %v", c.line, got, ok, c.want, c.ok)
		}
	}
}

func TestIsSh(t *testing.T) {
	for src, want := range map[string]bool{
		"#!/bin/sh\necho hi\n":          true,
		"#!/usr/bin/env sh\necho hi\n":  true,
		"#!/usr/bin/env -S sh -eu\n":    true, // env's own flags are skipped
		"#!/bin/bash\necho hi\n":        false,
		"#!/usr/bin/env bash\necho\n":   false,
		"echo no shebang at all\n":      false,
		"#!/usr/bin/env python3\nx=1\n": false,
	} {
		if got := IsSh(src); got != want {
			t.Errorf("IsSh(%q) = %v, want %v", src, got, want)
		}
	}
}

func TestInterpreterFromFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got, ok := InterpreterFromFile(write("script", "#!/usr/bin/env bash\necho hi\n")); got != "bash" || !ok {
		t.Errorf("InterpreterFromFile(script) = %q, %v; want %q, true", got, ok, "bash")
	}
	if got, ok := InterpreterFromFile(write("binary", "\x7fELF junk")); ok {
		t.Errorf("InterpreterFromFile(binary) = %q, true; want ok=false", got)
	}
	if _, ok := InterpreterFromFile(filepath.Join(dir, "missing")); ok {
		t.Error("InterpreterFromFile(missing) = ok; want false")
	}
	if _, ok := InterpreterFromFile(""); ok {
		t.Error(`InterpreterFromFile("") = ok; want false`)
	}
}

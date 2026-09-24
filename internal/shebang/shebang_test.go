package shebang

import "testing"

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

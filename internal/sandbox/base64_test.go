package sandbox

import (
	"bytes"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

func TestBase64RunsInProcess(t *testing.T) {
	root := t.TempDir()
	var out, stderr bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron("PATH="))
	cfg.Strict = true
	cfg.Stdout, cfg.Stderr = &out, &stderr
	script := `
		command -v base64
		printf hello | base64
		printf aGVsbG8= | base64 -d
		printf '\n'
		printf aGVsbG8= | base64 -D
		printf '\n'
		printf 'aG!Vs bG8=' | base64 --ignore-garbage --decode
		printf '\n'
	`
	if err := Run(cfg, "base64", script); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	want := "/opt/sandbox/bin/base64\naGVsbG8=\nhello\nhello\nhello\n"
	if got := out.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestBase64Wrap(t *testing.T) {
	root := t.TempDir()
	var out bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron("PATH="))
	cfg.Stdout = &out
	if err := Run(cfg, "base64-wrap", `printf 123456789 | base64 -w 4`); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(out.String()), "MTIz\nNDU2\nNzg5"; got != want {
		t.Errorf("wrapped output = %q, want %q", got, want)
	}
}

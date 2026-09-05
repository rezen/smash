package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

const abcSHA256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func TestSHA256SumRunsInProcess(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "abc.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron("PATH="))
	cfg.Strict = true
	cfg.Stdout, cfg.Stderr = &out, &stderr
	script := `
		command -v sha256sum
		sha256sum abc.txt
		printf abc | sha256sum -b -
	`
	if err := Run(cfg, "sha256sum", script); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	want := []string{
		"/opt/sandbox/bin/sha256sum",
		abcSHA256 + "  abc.txt",
		abcSHA256 + " *-",
	}
	if len(lines) != len(want) {
		t.Fatalf("output lines = %q, want %q", lines, want)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestSHA256SumCheck(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "abc.txt"), []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "checksums"), []byte(abcSHA256+"  abc.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron("PATH="))
	cfg.Stdout, cfg.Stderr = &out, &stderr
	if err := Run(cfg, "sha256sum-check", `sha256sum -c checksums`); err != nil {
		t.Fatalf("check: %v\nstderr=%s", err, stderr.String())
	}
	if got := out.String(); got != "abc.txt: OK\n" {
		t.Errorf("output = %q", got)
	}

	out.Reset()
	if err := os.WriteFile(filepath.Join(root, "abc.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Run(cfg, "sha256sum-bad", `sha256sum --quiet -c checksums`); err == nil {
		t.Fatal("mismatched checksum succeeded")
	}
	if got := out.String(); got != "abc.txt: FAILED\n" {
		t.Errorf("failure output = %q", got)
	}
}

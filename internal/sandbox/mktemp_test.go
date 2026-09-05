package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

func TestMktempRunsInProcessAndUsesTMPDIR(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "controlled-tmp")
	explicit := filepath.Join(root, "staging")
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(explicit, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron(
		"TMPDIR="+tmp,
		// An empty PATH proves that the host's mktemp binary is never used.
		"PATH=",
	))
	cfg.Strict = true
	cfg.Stdout, cfg.Stderr = &out, &stderr
	script := `
		file=$(mktemp)
		dir=$(mktemp -d)
		portable=$(mktemp -d -t portable.XXXXXXXX)
		explicit=$(mktemp -d "` + explicit + `/stage.XXXX")
		printf '%s\n' "$file" "$dir" "$portable" "$explicit"
	`
	if err := Run(cfg, "mktemp", script); err != nil {
		t.Fatalf("run: %v\nstderr=%s", err, stderr.String())
	}
	paths := strings.Fields(out.String())
	if len(paths) != 4 {
		t.Fatalf("paths = %q", out.String())
	}
	for i, name := range paths[:3] {
		if !pathWithin(tmp, name) {
			t.Errorf("path %d = %q, want it under TMPDIR %q", i, name, tmp)
		}
	}
	if !pathWithin(explicit, paths[3]) {
		t.Errorf("explicit template created %q, want it under %q", paths[3], explicit)
	}
	for i, name := range paths {
		info, err := os.Stat(name)
		if err != nil {
			t.Errorf("stat path %d: %v", i, err)
			continue
		}
		wantDir := i != 0
		if info.IsDir() != wantDir {
			t.Errorf("path %d IsDir = %v, want %v", i, info.IsDir(), wantDir)
		}
	}
}

func TestMktempOptions(t *testing.T) {
	root := t.TempDir()
	tmp := filepath.Join(root, "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cfg := NewConfig(root, root, expand.ListEnviron("TMPDIR="+tmp, "PATH="))
	cfg.Stdout = &out
	if err := Run(cfg, "mktemp-options", `mktemp -dq --suffix=.log name.XXXX`); err != nil {
		t.Fatal(err)
	}
	name := strings.TrimSpace(out.String())
	if filepath.Dir(name) != tmp || !strings.HasPrefix(filepath.Base(name), "name.") || !strings.HasSuffix(name, ".log") {
		t.Errorf("unexpected generated name %q", name)
	}
	if info, err := os.Stat(name); err != nil || !info.IsDir() {
		t.Errorf("generated directory: info=%v err=%v", info, err)
	}

	out.Reset()
	if err := Run(cfg, "mktemp-dry-run", `mktemp -u dry.XXXX`); err != nil {
		t.Fatal(err)
	}
	if name := strings.TrimSpace(out.String()); name == "" {
		t.Error("dry run did not print a name")
	} else if _, err := os.Stat(name); !os.IsNotExist(err) {
		t.Errorf("dry-run path %q exists or returned unexpected error: %v", name, err)
	}
}

package pathsafe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLexicallyWithin(t *testing.T) {
	cases := []struct {
		root, abs string
		want      bool
	}{
		{"/a/b", "/a/b/c", true},
		{"/a/b", "/a/b", true},
		{"/a/b", "/a", false},
		{"/a/b", "/a/bc", false}, // sibling with the root as a name prefix
		{"/a/b", "/a/b/../c", false},
	}
	for _, c := range cases {
		if got := LexicallyWithin(c.root, filepath.Clean(c.abs)); got != c.want {
			t.Errorf("LexicallyWithin(%q, %q) = %v, want %v", c.root, c.abs, got, c.want)
		}
	}
}

func TestWithinResolvesSymlinks(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	outside := filepath.Join(dir, "outside")
	for _, d := range []string{root, outside, filepath.Join(root, "real")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A symlink inside the root pointing outside must not count as inside.
	escape := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escape); err != nil {
		t.Fatal(err)
	}
	if Within(root, filepath.Join(escape, "f")) {
		t.Error("a symlink pointing outside the root counted as inside")
	}
	// A symlink inside the root pointing at another spot inside still counts.
	staging := filepath.Join(root, "staging")
	if err := os.Symlink(filepath.Join(root, "real"), staging); err != nil {
		t.Fatal(err)
	}
	if !Within(root, filepath.Join(staging, "f")) {
		t.Error("a symlinked staging directory inside the root counted as outside")
	}
	// The target need not exist: the deepest existing ancestor decides.
	if !Within(root, filepath.Join(root, "not", "yet", "created")) {
		t.Error("a to-be-created path under the root counted as outside")
	}
	if Within(root, filepath.Join(outside, "not", "yet")) {
		t.Error("a to-be-created path outside the root counted as inside")
	}
}

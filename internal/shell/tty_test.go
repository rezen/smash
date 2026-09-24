package shell

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSameOpenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	g, err := os.Open(path) // a second descriptor for the same file
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	if !SameOpenFile(f, f) {
		t.Error("SameOpenFile(f, f) = false; the identical *os.File must match")
	}
	if !SameOpenFile(g, f) {
		t.Error("SameOpenFile(g, f) = false; two descriptors on one file must match")
	}
	other, err := os.Create(filepath.Join(t.TempDir(), "other"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if SameOpenFile(other, f) {
		t.Error("SameOpenFile(other, f) = true; distinct files must not match")
	}
	if SameOpenFile(&strings.Builder{}, f) {
		t.Error("SameOpenFile(non-file, f) = true; a non-*os.File writer must not match")
	}
	if SameOpenFile(f, nil) {
		t.Error("SameOpenFile(f, nil) = true; want false")
	}
}

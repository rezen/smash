package gitconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// mkGitDir writes a .git directory holding a config with the given content.
func mkGitDir(t *testing.T, parent, config string) string {
	t.Helper()
	gitDir := filepath.Join(parent, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	return gitDir
}

const twoRemotes = `[core]
	bare = false
[remote "origin"]
	url = https://example.com/x/y.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[remote "mirror"]
	url = https://example.com/m.git
	pushurl = git@example.com:m.git
`

func TestFindGitDir(t *testing.T) {
	root := t.TempDir()
	gitDir := mkGitDir(t, root, "")
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindGitDir(nested); got != gitDir {
		t.Errorf("FindGitDir(%q) = %q, want %q", nested, got, gitDir)
	}
	if got := FindGitDir(root); got != gitDir {
		t.Errorf("FindGitDir(%q) = %q, want %q", root, got, gitDir)
	}
	// A .git FILE (worktree, submodule) is an entry too — the walk stops at it.
	wt := t.TempDir()
	pointer := filepath.Join(wt, ".git")
	if err := os.WriteFile(pointer, []byte("gitdir: elsewhere\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := FindGitDir(filepath.Join(wt, ".")); got != pointer {
		t.Errorf("FindGitDir over a .git file = %q, want %q", got, pointer)
	}
}

func TestRemoteURLs(t *testing.T) {
	gitDir := mkGitDir(t, t.TempDir(), twoRemotes)
	if url, push := RemoteURLs(gitDir, "origin"); url != "https://example.com/x/y.git" || push != "" {
		t.Errorf(`RemoteURLs(origin) = %q, %q`, url, push)
	}
	if url, push := RemoteURLs(gitDir, "mirror"); url != "https://example.com/m.git" || push != "git@example.com:m.git" {
		t.Errorf(`RemoteURLs(mirror) = %q, %q`, url, push)
	}
	if url, push := RemoteURLs(gitDir, "nowhere"); url != "" || push != "" {
		t.Errorf(`RemoteURLs(nowhere) = %q, %q; want "", ""`, url, push)
	}
	if url, push := RemoteURLs(filepath.Join(t.TempDir(), "missing"), "origin"); url != "" || push != "" {
		t.Errorf(`RemoteURLs(missing repo) = %q, %q; want "", ""`, url, push)
	}
}

func TestRemoteURLsThroughGitFile(t *testing.T) {
	base := t.TempDir()
	actual := filepath.Join(base, "actual")
	if err := os.MkdirAll(actual, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(actual, "config"), []byte(twoRemotes), 0o644); err != nil {
		t.Fatal(err)
	}
	wt := filepath.Join(base, "wt")
	if err := os.MkdirAll(wt, 0o755); err != nil {
		t.Fatal(err)
	}
	pointer := filepath.Join(wt, ".git")
	// A RELATIVE pointer resolves against the pointer file's directory.
	if err := os.WriteFile(pointer, []byte("gitdir: ../actual\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if url, _ := RemoteURLs(pointer, "origin"); url != "https://example.com/x/y.git" {
		t.Errorf("RemoteURLs through gitdir pointer = %q", url)
	}
	// A .git file that is not a pointer resolves to nothing — and must not
	// fall through to reading a "config" relative to the process cwd.
	bogus := filepath.Join(base, "bogus")
	if err := os.WriteFile(bogus, []byte("junk\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if url, push := RemoteURLs(bogus, "origin"); url != "" || push != "" {
		t.Errorf(`RemoteURLs(non-pointer file) = %q, %q; want "", ""`, url, push)
	}
}

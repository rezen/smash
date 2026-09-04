package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGitNamedRemote: `git fetch origin` is judged by the URL origin points at
// in .git/config — allowed for an on-list remote (here a file:// upstream on
// the prefix list, so nothing touches the network) and denied, naming the
// resolved URL, for an off-list one. --git-dir, -C, and a plain cwd all find
// the repository.
func TestGitNamedRemote(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	upstream := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.name=t", "-c", "user.email=t@x", "commit", "-q", "--allow-empty", "-m", "x"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = upstream
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	upstreamURL := "file://" + upstream

	mkRepo := func(t *testing.T, url string) string {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg := "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = " + url + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
		if err := os.WriteFile(filepath.Join(dir, ".git", "config"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	// A file:// remote reaches no network, so the egress guard lets it through
	// on that basis alone; AllowedPrefixes does not grant git anything (see
	// Policy.AllowsGit) and GitHosts cannot name a hostless URL.
	allowUpstream := func(c *Config) { c.Network.GitHosts = nil }

	t.Run("allowed via --git-dir", func(t *testing.T) {
		repo := mkRepo(t, upstreamURL)
		script := "git init -q " + repo + " && git --git-dir=" + repo + "/.git --work-tree=" + repo + " fetch origin main --depth=1 && echo fetched"
		out, stderr, err := runConfined(t, script, allowUpstream)
		if err != nil || !strings.Contains(out, "fetched") {
			t.Fatalf("err=%v out=%q stderr=%q", err, out, stderr)
		}
	})
	t.Run("allowed via -C", func(t *testing.T) {
		repo := mkRepo(t, upstreamURL)
		out, stderr, err := runConfined(t, "git init -q "+repo+" && git -C "+repo+" fetch origin && echo fetched", allowUpstream)
		if err != nil || !strings.Contains(out, "fetched") {
			t.Fatalf("err=%v out=%q stderr=%q", err, out, stderr)
		}
	})
	t.Run("allowed via cwd", func(t *testing.T) {
		repo := mkRepo(t, upstreamURL)
		out, stderr, err := runConfined(t, "git init -q "+repo+" && cd "+repo+" && git fetch && echo fetched", allowUpstream)
		if err != nil || !strings.Contains(out, "fetched") {
			t.Fatalf("err=%v out=%q stderr=%q", err, out, stderr)
		}
	})
	t.Run("denied off-list remote", func(t *testing.T) {
		repo := mkRepo(t, "https://evil.example/o/r")
		_, stderr, err := runConfined(t, "git -C "+repo+" fetch origin", allowUpstream)
		if err == nil || !strings.Contains(stderr, "egress denied: git → origin = https://evil.example/o/r") {
			t.Fatalf("err=%v stderr=%q", err, stderr)
		}
	})
	t.Run("denied unknown remote", func(t *testing.T) {
		repo := mkRepo(t, upstreamURL)
		_, stderr, err := runConfined(t, "git -C "+repo+" fetch nowhere", allowUpstream)
		if err == nil || !strings.Contains(stderr, "egress denied: git → nowhere\n") {
			t.Fatalf("err=%v stderr=%q", err, stderr)
		}
	})
}

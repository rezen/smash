// Package gitconfig reads the parts of a repository's on-disk git state the
// sandbox needs to judge egress: where the repository is (FindGitDir — the
// nearest-.git walk git itself does) and which URLs a remote name stands for
// (RemoteURLs). It exists so the egress guard can resolve a remote NAME
// ("origin") to the place it actually reaches without shelling out to git —
// git is the command being judged. Only the syntax git writes itself is
// understood — `[section "sub"]` headers and `key = value` lines — which is
// all that clone/remote produce.
package gitconfig

import (
	"os"
	"path/filepath"
	"strings"
)

// FindGitDir walks up from dir to the nearest .git entry (directory or
// file); "" when no ancestor holds one.
func FindGitDir(dir string) string {
	for {
		g := filepath.Join(dir, ".git")
		if _, err := os.Lstat(g); err == nil {
			return g
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// RemoteURLs reads the url and pushurl of [remote "name"] from the
// repository whose .git entry is gitDir — a directory, or a worktree's or
// submodule's `gitdir: PATH` pointer file, which is followed first. Both
// results are "" when there is no such repository or remote; pushURL is ""
// for the common remote that pushes where it fetches.
func RemoteURLs(gitDir, name string) (url, pushURL string) {
	if fi, err := os.Stat(gitDir); err == nil && !fi.IsDir() { // "gitdir: PATH"
		gitDir = followGitFile(gitDir)
		if gitDir == "" {
			return "", ""
		}
	}
	data, err := os.ReadFile(filepath.Join(gitDir, "config"))
	if err != nil {
		return "", ""
	}
	inRemote := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inRemote = line == `[remote "`+name+`"]`
			continue
		}
		if !inRemote {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			switch strings.TrimSpace(k) {
			case "url":
				url = strings.TrimSpace(v)
			case "pushurl":
				pushURL = strings.TrimSpace(v)
			}
		}
	}
	return url, pushURL
}

// followGitFile reads a `gitdir: PATH` pointer file; "" if it isn't one.
func followGitFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return ""
	}
	target = strings.TrimSpace(target)
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Join(filepath.Dir(p), target)
}

// Package pathsafe answers "is this path inside that directory?" for paths
// an untrusted script chose. Lexical containment is not enough on its own —
// a symlink with a name inside the root can point its target outside it — so
// Within resolves symlinks on both sides before comparing.
package pathsafe

import (
	"path/filepath"
	"strings"
)

// LexicallyWithin reports whether abs is lexically inside root. It says
// nothing about symlinks; Within is the one to use on a path a script chose.
func LexicallyWithin(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Within reports whether target is inside root once symlinks are resolved
// on both sides. The target itself need not exist — it is often a file about
// to be created — so the deepest ancestor that does exist is what gets
// resolved: a symlinked staging directory inside the root still counts as
// inside, and one pointing out of it does not. Resolving root too is what
// makes this work on macOS, where /var is a symlink to /private/var and the
// two spellings would otherwise never match.
func Within(root, target string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = root
	}
	dir := target
	for {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			rest, err := filepath.Rel(dir, target)
			if err != nil {
				return false
			}
			return LexicallyWithin(realRoot, filepath.Join(real, rest))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

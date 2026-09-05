package sandbox

// CallHandler shims. A CallHandler runs on every simple command — builtins
// included — before it executes, and may rewrite its args. A few mvdan/sh-specific
// papercuts are patched here so real-world installers run unmodified.

import (
	"context"
	"strings"

	"github.com/rezen/smash/internal/tool"
)

// detectionCallHandler is the single CallHandler; it dispatches to the shims.
func detectionCallHandler(ctx context.Context, args []string) ([]string, error) {
	args = shimCommandDefaultPath(args)
	if rewritten, ok := shimToolProbe(args); ok {
		return rewritten, nil
	}
	if rewritten, ok := shimDeclarationBuiltin(args); ok {
		return rewritten, nil
	}
	return args, nil
}

// shimCommandDefaultPath drops the -p from `command -p NAME …`, which mvdan/sh
// rejects ("command: invalid option \"-p\""). -p only swaps in the system's
// default PATH for the lookup; here the allow-list decides what may run
// regardless of where it resolves, so plain `command NAME …` is equivalent.
// Other letters in the same cluster (`-pv`) are kept.
func shimCommandDefaultPath(args []string) []string {
	if len(args) < 2 || args[0] != "command" || !strings.HasPrefix(args[1], "-") || !strings.Contains(args[1], "p") {
		return args
	}
	rest := strings.ReplaceAll(args[1], "p", "")
	out := append([]string{"command"}, args[2:]...)
	if rest != "-" {
		out = append([]string{"command", rest}, args[2:]...)
	}
	return out
}

// shimToolProbe makes commands implemented in-process visible
// to `command -v`, even if no host binary exists. Without this, installers
// may skip a portable implementation before they ever invoke it. The path is
// cosmetic; installers occasionally inspect it (for example, rejecting snap).
func shimToolProbe(args []string) ([]string, bool) {
	if len(args) >= 3 && args[0] == "command" && (args[1] == "-v" || args[1] == "-V") && tool.Is(args[2]) {
		return []string{"echo", "/opt/sandbox/bin/" + args[2]}, true
	}
	return nil, false
}

// shimDeclarationBuiltin works around mvdan/sh implementing typeset/declare only
// as parser KEYWORDS, not runtime command builtins. A backslash-escaped
// `\typeset a b c` (rvm line 798) parses as a plain command and fails
// "unsupported builtin" — exit 2, which aborts scripts under `set -e`. Only the
// escaped/command form reaches a CallHandler (keyword forms are DeclClause nodes
// and never do), so rewriting a bare-name declaration to a successful no-op is
// safe and leaves the working keyword forms untouched. Declarations carrying an
// assignment are passed through so a name=value is never silently dropped.
func shimDeclarationBuiltin(args []string) ([]string, bool) {
	if len(args) == 0 || (args[0] != "typeset" && args[0] != "declare") {
		return nil, false
	}
	for _, a := range args[1:] {
		if strings.Contains(a, "=") {
			return nil, false
		}
	}
	return []string{"true"}, true // bare declaration → successful no-op
}

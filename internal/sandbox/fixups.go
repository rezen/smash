package sandbox

// Fixups: AST rewrites that make mvdan/sh behave like bash where the two
// differ in ways real installers trip over. Each is exact — it changes the
// program only where the interpreter would otherwise do the wrong thing.

import "mvdan.cc/sh/v3/syntax"

// rewriteSubshellReturns turns `return` into `exit` where it runs in a
// subshell inside a function. Bash forks the subshell, so `return N` there
// ends only the subshell with status N — exactly what `exit N` does. mvdan/sh
// (v3.14.0, and master at the time of writing) forgets it is inside a function
// when it creates a sub-runner, and fails the command with "return: can only be
// done from a func or sourced script". That breaks the godownloader idiom
// `hash=$(sha256sum "$f") || return 1` the moment a tool is missing, and any
// `( … return … )` in a function body. The rewrite is exact because the
// interpreter also stops `exit` at the subshell boundary.
//
// Subshells are `( … )`, `$( … )`, `<( … )`/`>( … )`, a `cmd &` statement, and
// every pipeline stage but the last (mvdan/sh runs the last stage in the
// parent, like bash's lastpipe). A function defined inside a subshell starts a
// fresh scope: its own `return` is a real return again.
func rewriteSubshellReturns(f *syntax.File) { rewriteReturns(f, returnScope{}) }

type returnScope struct{ inFunc, inSub bool }

func rewriteReturns(root syntax.Node, cur returnScope) {
	var stack []returnScope
	syntax.Walk(root, func(n syntax.Node) bool {
		if n == nil { // leaving a node: restore the scope of its parent
			cur, stack = stack[len(stack)-1], stack[:len(stack)-1]
			return true
		}
		stack = append(stack, cur)
		switch x := n.(type) {
		case *syntax.FuncDecl:
			cur = returnScope{inFunc: true}
		case *syntax.Subshell, *syntax.CmdSubst, *syntax.ProcSubst:
			cur.inSub = true
		case *syntax.Stmt:
			if x.Background || x.Coprocess {
				cur.inSub = true
			}
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				rewriteReturns(x.X, returnScope{inFunc: cur.inFunc, inSub: true})
				rewriteReturns(x.Y, cur)
				stack = stack[:len(stack)-1] // Walk skips f(nil) when we return false
				return false
			}
		case *syntax.CallExpr:
			if cur.inFunc && cur.inSub && len(x.Args) > 0 && len(x.Args[0].Parts) == 1 {
				if lit, ok := x.Args[0].Parts[0].(*syntax.Lit); ok && lit.Value == "return" {
					lit.Value = "exit"
				}
			}
		}
		return true
	})
}

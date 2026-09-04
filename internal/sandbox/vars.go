package sandbox

// Two views of a script's variables.
//
// RunVars is dynamic: the variable table after the interpreter has finished, so
// every value is resolved — branches taken, "${X:-default}" applied, command
// substitutions run. Assignments is static: every NAME=value the parser finds,
// in source order, with the right-hand side as written. It needs no execution
// and no allow-list, but cannot know which branch a script takes.
//
// mvdan/sh offers no hook on assignment itself (a bare `A=b` is not a command,
// so neither the CallHandler nor the ExecHandler sees it); these two views are
// the before and after around that gap.

import (
	"context"
	"maps"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// Vars is the variable table at the end of a run: everything the script
// assigned, plus the environment it inherited from Config.Env and the HOME/UID
// defaults the interpreter fills in. Values are fully resolved. Variables set
// inside a confined `sh -c` belong to that sub-run and are not included, just
// as with a real sh.
type Vars map[string]expand.Variable

// Names returns the variable names in sorted order.
func (v Vars) Names() []string {
	return slices.Sorted(maps.Keys(v))
}

// RunVars is Run, additionally returning the final variable table. The table is
// returned even when the script fails, so a post-run audit can see how far it
// got and with which values.
func RunVars(cfg Config, name, src string) (Vars, error) {
	cfg = cfg.normalized()
	cfg.Posix = cfg.Posix || shebangIsSh(src)
	prog, err := parseBash(name, src)
	if err != nil {
		return nil, err
	}
	runner, err := buildRunner(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	err = runner.Run(ctx, prog)
	return Vars(maps.Clone(runner.Vars)), err
}

// Assignment is one NAME=value the parser found.
type Assignment struct {
	Name   string
	Value  string // the assigned string when Static; otherwise the right-hand side as written
	Line   uint
	Append bool // +=
	Static bool // Value contains no expansion, so the shell assigns it verbatim
}

// Assignments walks src's AST and lists every variable assignment in source
// order: plain `A=b`, command prefixes `A=b cmd`, and the declaration keywords
// (local, export, declare, typeset, readonly). Nothing runs, so a value like
// "$UV_DOWNLOAD_URL" is reported as written unless Static is true. Naked
// declarations (`local x`) and arithmetic assignments inside (( )) are not
// listed.
func Assignments(name, src string) ([]Assignment, error) {
	prog, err := parseBash(name, src)
	if err != nil {
		return nil, err
	}
	printer := syntax.NewPrinter()
	var out []Assignment
	syntax.Walk(prog, func(n syntax.Node) bool {
		a, ok := n.(*syntax.Assign)
		if !ok || a.Name == nil || a.Naked || (a.Value == nil && a.Array == nil) {
			return true
		}
		as := Assignment{Name: a.Name.Value, Line: a.Pos().Line(), Append: a.Append}
		switch {
		case a.Array != nil: // the printer has no bare-array mode: print the whole assignment
			_, as.Value, _ = strings.Cut(printNode(printer, a), "=")
		case isStaticWord(a.Value):
			as.Value, _ = expand.Literal(nil, a.Value)
			as.Static = true
		default:
			as.Value = printNode(printer, a.Value)
		}
		out = append(out, as)
		return true
	})
	return out, nil
}

// isStaticWord reports whether w is made only of literals and quoted literals,
// so that expanding it cannot depend on the environment.
func isStaticWord(w *syntax.Word) bool {
	for i, p := range w.Parts {
		switch p := p.(type) {
		case *syntax.Lit:
			if i == 0 && strings.HasPrefix(p.Value, "~") { // tilde expansion reads HOME
				return false
			}
		case *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				if _, ok := q.(*syntax.Lit); !ok {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}

// printNode renders a node back to its shell source text.
func printNode(p *syntax.Printer, n syntax.Node) string {
	var sb strings.Builder
	_ = p.Print(&sb, n)
	return sb.String()
}

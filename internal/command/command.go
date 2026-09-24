// Package command models the shell commands a sandbox has to reason about.
//
// Each command family is a concrete type — Curl, Openssl, Git, Sudo, … — that
// implements Command. Extra behaviour is exposed by satisfying small capability
// interfaces (Networked, Wrapper, ScriptRunner, Downloader, Structured),
// discovered by type assertion. Guards program against those interfaces, never
// against a big switch on the command name.
//
// The package is pure: it parses argv slices and renders them back. It knows
// nothing about mvdan/sh, processes, or the network.
package command

import "path/filepath"

// Command identifies and parses a family of shell commands.
type Command interface {
	Names() []string
	Parse(args []string) ParsedCommand
}

// Networked is implemented by commands capable of network egress.
type Networked interface {
	// Egress reports whether THIS invocation reaches out, and to where.
	Egress(p ParsedCommand) (target string, networked bool)
}

// Wrapper is implemented by commands that prefix another command (sudo/env/…).
type Wrapper interface {
	// Unwrap returns the inner command argv from a full argv, or nil.
	Unwrap(args []string) []string
}

// ScriptRunner is implemented by shells that run a `-c SCRIPT` string.
type ScriptRunner interface {
	DashC(args []string) (script string, params []string, ok bool)
}

// PathMutator is implemented by commands that change files' mode, ownership
// or attributes (chmod, chown, setfacl, …). Targets reports the paths an
// invocation mutates and whether it recurses into them, so a guard can scope
// mutations to the sandbox root.
type PathMutator interface {
	Targets(p ParsedCommand) (paths []string, recursive bool)
}

// Builtin marks a safe local command: a text/file/archive tool with no network
// reach. The unexported method keeps the marker closed to this package.
type Builtin interface {
	Command
	builtin()
}

// ParsedCommand is the normalized parse of one invocation. It carries the
// Command that produced it, so capability lookups can delegate to that type.
type ParsedCommand struct {
	cmd        Command
	raw        []string // original argv, for order-sensitive params (e.g. find)
	attached   Set      // flags whose value is glued on (`-i.bak`), for Args
	subIndex   int      // raw index of Subcommand, for grammars that split there (docker); 0 = none
	Name       string
	Subcommand string
	Flags      map[string][]string
	Operands   []string
}

// Command returns the Command that parsed this invocation, or nil if unknown.
func (p ParsedCommand) Command() Command { return p.cmd }

// Argv returns the original argv this command was parsed from.
func (p ParsedCommand) Argv() []string { return p.raw }

// HasFlag reports whether any of the given flags is present.
func (p ParsedCommand) HasFlag(names ...string) bool {
	for _, n := range names {
		if _, ok := p.Flags[n]; ok {
			return true
		}
	}
	return false
}

// FlagValue returns the first non-empty value of a flag; ok is true whenever
// the flag is present, even with an empty value.
func (p ParsedCommand) FlagValue(name string) (string, bool) {
	vs, ok := p.Flags[name]
	if !ok {
		return "", false
	}
	for _, v := range vs {
		if v != "" {
			return v, true
		}
	}
	return "", true
}

// FirstValue returns the first non-empty value among flag aliases
// (e.g. "-o", "--output").
func (p ParsedCommand) FirstValue(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := p.FlagValue(n); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// Values concatenates the values of all the given flag aliases, in argument
// order per alias.
func (p ParsedCommand) Values(names ...string) []string {
	var out []string
	for _, n := range names {
		out = append(out, p.Flags[n]...)
	}
	return out
}

// Egress reports whether this invocation reaches the network, and where. It is
// false for commands that are not Networked.
func (p ParsedCommand) Egress() (target string, networked bool) {
	if n, ok := p.cmd.(Networked); ok {
		return n.Egress(p)
	}
	return "", false
}

// baseName strips any directory from a command path (`/usr/bin/curl` → `curl`).
func baseName(name string) string { return filepath.Base(name) }

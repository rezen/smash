package command

import (
	"fmt"
	"maps"
	"slices"
)

// Set is a set of strings: flag names, command names, allow-list entries.
type Set map[string]bool

// NewSet builds a Set from names.
func NewSet(names ...string) Set {
	s := make(Set, len(names))
	for _, n := range names {
		s[n] = true
	}
	return s
}

// Clone returns an independent copy; cloning a nil Set yields an empty one.
func (s Set) Clone() Set {
	if s == nil {
		return Set{}
	}
	return maps.Clone(s)
}

// With returns a copy of s with names added.
func (s Set) With(names ...string) Set {
	c := s.Clone()
	for _, n := range names {
		c[n] = true
	}
	return c
}

// Names returns the members in sorted order.
func (s Set) Names() []string { return slices.Sorted(maps.Keys(s)) }

// Registry maps command names to the Command that parses them. Every name is
// registered at most once: a Builtin can never shadow a Networked or Wrapper
// command of the same name (which once let `env … curl` run unconfined).
type Registry struct {
	byName map[string]Command
	cmds   []Command
}

// NewRegistry builds a Registry, rejecting duplicate names.
func NewRegistry(cmds ...Command) (*Registry, error) {
	r := &Registry{byName: make(map[string]Command)}
	for _, c := range cmds {
		for _, n := range c.Names() {
			if prev, dup := r.byName[n]; dup {
				return nil, fmt.Errorf("command %q registered twice (%T and %T)", n, prev, c)
			}
			r.byName[n] = c
		}
		r.cmds = append(r.cmds, c)
	}
	return r, nil
}

// MustRegistry is NewRegistry that panics on a duplicate name.
func MustRegistry(cmds ...Command) *Registry {
	r, err := NewRegistry(cmds...)
	if err != nil {
		panic(err)
	}
	return r
}

// Lookup returns the Command registered for name (a bare name or a path), or nil.
func (r *Registry) Lookup(name string) Command { return r.byName[baseName(name)] }

// Parse parses args with the registered Command, or generically if unknown.
func (r *Registry) Parse(args []string) ParsedCommand {
	if len(args) == 0 {
		return ParsedCommand{Flags: map[string][]string{}}
	}
	cmd := r.Lookup(args[0])
	var p ParsedCommand
	if cmd != nil {
		p = cmd.Parse(args)
	} else {
		p = Spec{}.Parse(args)
	}
	p.cmd = cmd
	p.Name = baseName(args[0])
	return p
}

// Commands returns the registered commands in registration order.
func (r *Registry) Commands() []Command { return slices.Clone(r.cmds) }

// BuiltinNames returns every name registered by a Builtin command.
func (r *Registry) BuiltinNames() []string {
	var names []string
	for _, c := range r.cmds {
		if _, ok := c.(Builtin); ok {
			names = append(names, c.Names()...)
		}
	}
	return names
}

// Default is the registry of every command family this package knows.
var Default = MustRegistry(defaultCommands()...)

func defaultCommands() []Command {
	var all []Command
	all = append(all, networkCommands...)
	all = append(all, Shell{})
	all = append(all, wrapperCommands...)
	all = append(all, packageManagers...)
	for _, b := range builtinCommands {
		all = append(all, b)
	}
	for _, b := range fileCommands {
		all = append(all, b)
	}
	return all
}

// Lookup is Default.Lookup.
func Lookup(name string) Command { return Default.Lookup(name) }

// Parse is Default.Parse.
func Parse(args []string) ParsedCommand { return Default.Parse(args) }

// BuiltinNames is Default.BuiltinNames.
func BuiltinNames() []string { return Default.BuiltinNames() }

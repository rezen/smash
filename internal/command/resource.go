package command

// Resources: what an invocation touches, for audit logs. Every ParsedCommand
// can describe itself as "name: action kind value, …" — e.g.
// "curl: fetch url https://x/y, write path out.tgz" — so a log line names the
// resource and the operation instead of echoing argv. Values that could carry
// secrets (headers, cookies, passwords) are never resources.
//
// Where the description comes from, in order:
//
//  1. The command implements Describer (resources need logic: rsync's remote
//     vs local operands, find's -exec, install's sources vs destination).
//  2. The command is Structured: fields of its params struct tagged
//     resource:"kind,action" are the resources, in field order. An optional
//     third part names the stream used when the field is empty —
//     resource:"path,read,stdin" — because a tool with no file operand is
//     usually reading a pipe, and that should be visible in the log.
//  3. The command is Networked and this invocation egresses: one resource of
//     the egress target, kind guessed from its shape.
//  4. Otherwise every operand, kind "operand".

import (
	"reflect"
	"strings"
)

// Resource is one thing an invocation interacts with.
type Resource struct {
	Kind   string // url, host, path, repo, image, database, mode, script, operand, …
	Action string // fetch, connect, read, write, modify, apply, run, … ("" = unspecified)
	Value  string
}

func (r Resource) String() string {
	s := r.Kind
	if r.Action != "" {
		s = r.Action + " " + s
	}
	if r.Value != "" {
		s += " " + r.Value
	}
	return s
}

// Describer is implemented by commands that name their resources explicitly.
type Describer interface {
	Resources(p ParsedCommand) []Resource
}

// Resources lists what this invocation touches (see the package doc for the
// precedence).
func (p ParsedCommand) Resources() []Resource {
	if d, ok := p.cmd.(Describer); ok {
		return d.Resources(p)
	}
	if s, ok := p.cmd.(Structured); ok {
		return resourcesOf(s.Params(p))
	}
	if target, networked := p.Egress(); networked {
		return []Resource{{Kind: kindOf(target), Action: "connect", Value: target}}
	}
	return operandResources(p, "operand", "", false)
}

// Describe renders "name: resource, resource" — the audit-log line.
func (p ParsedCommand) Describe() string {
	rs := p.Resources()
	if len(rs) == 0 {
		return p.Name
	}
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = r.String()
	}
	return p.Name + ": " + strings.Join(parts, ", ")
}

// resourcesOf collects the resource-tagged fields of a params struct.
func resourcesOf(params any) []Resource {
	v := reflect.ValueOf(params)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	var rs []Resource
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tag, ok := t.Field(i).Tag.Lookup("resource")
		if !ok {
			continue
		}
		parts := strings.SplitN(tag, ",", 3)
		kind, action, stream := parts[0], "", ""
		if len(parts) > 1 {
			action = parts[1]
		}
		if len(parts) > 2 {
			stream = parts[2]
		}
		n := 0
		switch fv := v.Field(i); fv.Kind() {
		case reflect.String:
			if s := fv.String(); s != "" && s != "-" {
				rs = append(rs, Resource{Kind: kind, Action: action, Value: s})
				n++
			}
		case reflect.Slice:
			for _, s := range fv.Interface().([]string) {
				rs = append(rs, Resource{Kind: kind, Action: action, Value: s})
				n++
			}
		}
		if n == 0 && stream != "" {
			rs = append(rs, streamResource(stream, action))
		}
	}
	return rs
}

// streamResource is the resource for data flowing through a pipe.
func streamResource(stream, action string) Resource {
	if action == "" {
		if stream == "stdin" {
			action = "read"
		} else {
			action = "write"
		}
	}
	return Resource{Kind: stream, Action: action}
}

// operandResources tags every operand with kind; with none and stdin set, the
// tool is reading a pipe.
func operandResources(p ParsedCommand, kind, action string, stdin bool) []Resource {
	if len(p.Operands) == 0 {
		if stdin {
			return []Resource{streamResource("stdin", "read")}
		}
		return nil
	}
	rs := make([]Resource, 0, len(p.Operands))
	for _, o := range p.Operands {
		rs = append(rs, Resource{Kind: kind, Action: action, Value: o})
	}
	return rs
}

// filesOrStdin tags files as read paths, or stdin when there are none.
func filesOrStdin(files []string) []Resource {
	if len(files) == 0 {
		return []Resource{streamResource("stdin", "read")}
	}
	rs := make([]Resource, 0, len(files))
	for _, f := range files {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: f})
	}
	return rs
}

// kindOf guesses a resource kind from a target's shape.
func kindOf(target string) string {
	switch {
	case strings.Contains(target, "://"):
		return "url"
	case strings.Contains(target, "@"):
		return "host"
	case strings.LastIndexByte(target, ':') > 0 && isDigits(target[strings.LastIndexByte(target, ':')+1:]):
		return "socket"
	}
	return "host"
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// pathResources tags each operand as remote (kind "remote") or local (kind
// "path") using remoteOperand's rule. Shared by scp and rsync.
func pathResources(paths []string, action string) []Resource {
	rs := make([]Resource, 0, len(paths))
	for _, o := range paths {
		kind := "path"
		if _, remote := remoteOperand([]string{o}); remote {
			kind = "remote"
		}
		rs = append(rs, Resource{Kind: kind, Action: action, Value: o})
	}
	return rs
}

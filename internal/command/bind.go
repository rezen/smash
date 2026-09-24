package command

// Tag-driven params. A typed Params struct declares its flags once, as struct
// tags, and this file derives everything else from them: bind fills the struct
// from a ParsedCommand, render turns it back into argv, and specOf produces the
// command's parse Spec — so the parser, the reader and the renderer can never
// drift apart.
//
//	Field type   Tag                       Meaning
//	bool         flag:"-s,--silent"        present if any alias is present
//	string       flag:"-o,--output"        first non-empty value across aliases
//	[]string     flag:"-H,--header"        every value across aliases
//	string       operand:"url"             the URL operand (first with a scheme, else first)
//	string       operand:"first"           the first operand
//	[]string     operand:"rest"            every operand after the first
//	[]string     operand:"all"             every operand
//	string       role:"subcommand"         the subcommand
//	[]string     role:"rest"               every flag not bound to another field, as
//	                                       name[,value] pairs sorted by name
//
// The first alias of a flag tag is the canonical spelling render emits.
// Anything a command accepts but does not model (timeouts, retries, …) is
// passed to specOf as extra value flags so the parser still consumes their
// values.

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
)

type boundField struct {
	index   []int        // field index path (embedded structs flatten)
	kind    reflect.Kind // Bool, String or Slice (of string)
	flags   []string
	operand string // "", "url", "first", "all"
	role    string // "", "subcommand", "rest"
}

var fieldCache sync.Map // reflect.Type → []boundField

// fieldsOf returns the tagged fields of a params struct type, validated once.
// Anonymous embedded structs flatten in place, so families of commands can
// share a common globals struct.
func fieldsOf(t reflect.Type) []boundField {
	if cached, ok := fieldCache.Load(t); ok {
		return cached.([]boundField)
	}
	fields := collectFields(t, nil)
	fieldCache.Store(t, fields)
	return fields
}

func collectFields(t reflect.Type, base []int) []boundField {
	var fields []boundField
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		index := append(append([]int{}, base...), i)
		if sf.Anonymous && sf.Type.Kind() == reflect.Struct {
			fields = append(fields, collectFields(sf.Type, index)...)
			continue
		}
		f := boundField{index: index, kind: sf.Type.Kind()}
		if tag, ok := sf.Tag.Lookup("flag"); ok {
			f.flags = strings.Split(tag, ",")
		}
		f.operand = sf.Tag.Get("operand")
		f.role = sf.Tag.Get("role")
		if len(f.flags) == 0 && f.operand == "" && f.role == "" {
			continue // untagged: not part of the command line
		}
		isStrings := f.kind == reflect.Slice && sf.Type.Elem().Kind() == reflect.String
		okKind := f.kind == reflect.String || isStrings || (f.kind == reflect.Bool && len(f.flags) > 0)
		if !okKind || (f.role == "rest" && !isStrings) || ((f.operand == "all" || f.operand == "rest") && !isStrings) {
			panic(fmt.Sprintf("command: %s.%s: unsupported type %s for its tag", t.Name(), sf.Name, sf.Type))
		}
		fields = append(fields, f)
	}
	return fields
}

// specOf derives a parse Spec from a params struct: every string/[]string flag
// is a value flag, a subcommand field enables subcommand parsing. extraValueFlags
// are accepted-but-unmodelled flags that also take a value.
func specOf(proto any, clusterShort bool, extraValueFlags ...string) Spec {
	s := Spec{ClusterShort: clusterShort, ValueFlags: NewSet(extraValueFlags...)}
	for _, f := range fieldsOf(reflect.TypeOf(proto)) {
		if f.role == "subcommand" {
			s.Subcommand = true
		}
		if f.kind != reflect.Bool {
			for _, fl := range f.flags {
				s.ValueFlags[fl] = true
			}
		}
	}
	return s
}

// stopAtOperand returns s with POSIX-style option parsing (see Spec).
func stopAtOperand(s Spec) Spec { s.StopAtOperand = true; return s }

// bind fills dst (a pointer to a params struct) from p.
func bind(p ParsedCommand, dst any) {
	v := reflect.ValueOf(dst).Elem()
	fields := fieldsOf(v.Type())
	for _, f := range fields {
		fv := v.FieldByIndex(f.index)
		switch {
		case f.role == "subcommand":
			fv.SetString(p.Subcommand)
		case f.role == "rest":
			fv.Set(reflect.ValueOf(restFlags(p, fields)))
		case f.operand == "url":
			s, _ := urlOperand(p)
			fv.SetString(s)
		case f.operand == "first":
			if len(p.Operands) > 0 {
				fv.SetString(p.Operands[0])
			}
		case f.operand == "all":
			fv.Set(reflect.ValueOf(append([]string(nil), p.Operands...)))
		case f.operand == "rest":
			if len(p.Operands) > 1 {
				fv.Set(reflect.ValueOf(append([]string(nil), p.Operands[1:]...)))
			}
		case f.kind == reflect.Bool:
			fv.SetBool(p.HasFlag(f.flags...))
		case f.kind == reflect.String:
			s, _ := p.FirstValue(f.flags...)
			fv.SetString(s)
		default:
			fv.Set(reflect.ValueOf(p.Values(f.flags...)))
		}
	}
}

// restFlags flattens every flag not claimed by a tagged field into
// name[,value] pairs, sorted by name for a deterministic rendering.
func restFlags(p ParsedCommand, fields []boundField) []string {
	bound := Set{}
	for _, f := range fields {
		for _, fl := range f.flags {
			bound[fl] = true
		}
	}
	names := make([]string, 0, len(p.Flags))
	for name := range p.Flags {
		if !bound[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var rest []string
	for _, name := range names {
		for _, v := range p.Flags[name] {
			rest = append(rest, name)
			if v != "" {
				rest = append(rest, v)
			}
		}
	}
	return rest
}

// render turns a params struct back into argv: name, then fields in
// declaration order (adjacent short bool flags cluster into -sSfL when
// clusterShort is set) — so a subcommand field renders where it is declared,
// after any global flags — rest flags where declared, operands last.
func render(name string, src any, clusterShort bool) []string {
	v := reflect.ValueOf(src)
	fields := fieldsOf(v.Type())
	out := []string{name}
	var short []byte
	flush := func() {
		if len(short) > 0 {
			out = append(out, "-"+string(short))
			short = nil
		}
	}
	var operands []string
	for _, f := range fields {
		fv := v.FieldByIndex(f.index)
		switch {
		case f.role == "subcommand":
			flush()
			if s := fv.String(); s != "" {
				out = append(out, s)
			}
		case f.role == "rest":
			flush()
			out = append(out, fv.Interface().([]string)...)
		case f.operand == "all" || f.operand == "rest":
			operands = append(operands, fv.Interface().([]string)...)
		case f.operand != "":
			if s := fv.String(); s != "" {
				operands = append(operands, s)
			}
		case f.kind == reflect.Bool:
			if !fv.Bool() {
				continue
			}
			if fl := f.flags[0]; clusterShort && len(fl) == 2 {
				short = append(short, fl[1])
			} else {
				flush()
				out = append(out, fl)
			}
		case f.kind == reflect.String:
			if s := fv.String(); s != "" {
				flush()
				out = append(out, f.flags[0], s)
			}
		default:
			for _, s := range fv.Interface().([]string) {
				flush()
				out = append(out, f.flags[0], s)
			}
		}
	}
	flush()
	return append(out, operands...)
}

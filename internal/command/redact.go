package command

// Redaction for logs. A command line can carry credentials — curl -H
// 'Authorization: …', mysql -p PASS, --token … — so anything rendered into an
// audit record goes through Redact first. Typed params mark secret fields with
// a `secret:"true"` tag; the generic form redacts the values of well-known
// secret flags, plus any the command declares via SecretFlags.

import (
	"reflect"
	"strings"
)

// Redacted is the placeholder that replaces a secret value. It has no shell
// metacharacters, so it renders unquoted in a command line.
const Redacted = "REDACTED"

// SecretFlagger is implemented by commands with additional secret-bearing flags
// (e.g. mysql's -p) beyond the global list.
type SecretFlagger interface {
	SecretFlags() []string
}

// secretFlags are redacted for every command when rendering the generic form.
// For a command the registry does not know, only the --flag=value form can be
// redacted: without a Spec the parser cannot tell that `--token abc` takes a
// value. Register a command (or a NetTool with Secrets) to cover that form.
var secretFlags = NewSet(
	"-H", "--header", "--cookie", "--password", "--passwd", "--password-file",
	"--token", "--auth", "--api-key", "--apikey", "--secret", "--access-key", "--secret-key",
	"--data", "--data-raw", "--data-binary", "--data-urlencode", "--post-data",
)

// Redacted returns a copy of p with secret flag values replaced.
func (p ParsedCommand) Redacted() ParsedCommand {
	extra := Set{}
	if sf, ok := p.cmd.(SecretFlagger); ok {
		extra = NewSet(sf.SecretFlags()...)
	}
	out := p
	out.Flags = make(map[string][]string, len(p.Flags))
	for name, vals := range p.Flags {
		if !secretFlags[name] && !extra[name] {
			out.Flags[name] = vals
			continue
		}
		red := make([]string, len(vals))
		for i, v := range vals {
			if v != "" {
				v = Redacted
			}
			red[i] = v
		}
		out.Flags[name] = red
	}
	return out
}

// Redact returns a copy of params with every `secret:"true"` field replaced by
// Redacted (strings) or a slice of Redacted (string slices). A `role:"rest"`
// slice may instead carry `secret:"-flag,-flag"`: the value following any of
// those flag names (and any global secret flag) is redacted. A generic
// ParsedCommand is redacted by flag name instead. Other Params are returned
// as-is.
func Redact(params Params) Params {
	if p, ok := params.(ParsedCommand); ok {
		return p.Redacted()
	}
	v := reflect.ValueOf(params)
	if v.Kind() != reflect.Struct {
		return params
	}
	cp := reflect.New(v.Type()).Elem()
	cp.Set(v)
	for i := 0; i < v.NumField(); i++ {
		sf := v.Type().Field(i)
		tag := sf.Tag.Get("secret")
		if tag == "" {
			continue
		}
		if tag != "true" { // a rest slice with its own secret flag names
			if f := cp.Field(i); f.Kind() == reflect.Slice {
				f.Set(reflect.ValueOf(redactPairs(f.Interface().([]string), NewSet(strings.Split(tag, ",")...))))
			}
			continue
		}
		switch f := cp.Field(i); f.Kind() {
		case reflect.String:
			if f.String() != "" {
				f.SetString(Redacted)
			}
		case reflect.Slice:
			n := f.Len()
			red := make([]string, n)
			for j := range red {
				red[j] = Redacted
			}
			f.Set(reflect.ValueOf(red))
		}
	}
	return cp.Interface().(Params)
}

// redactPairs redacts the value that follows a secret flag in a flat
// name[,value] list (the shape of a rest slice).
func redactPairs(rest []string, extra Set) []string {
	out := append([]string(nil), rest...)
	for i := 0; i+1 < len(out); i++ {
		if (secretFlags[out[i]] || extra[out[i]]) && !strings.HasPrefix(out[i+1], "-") {
			out[i+1] = Redacted
			i++
		}
	}
	return out
}

// RedactedArgv returns the original argv with secret flag values replaced —
// the true command line as run, safe to log. Both `-p VALUE` and
// `--flag=VALUE` forms are handled.
func (p ParsedCommand) RedactedArgv() []string {
	extra := Set{}
	if sf, ok := p.cmd.(SecretFlagger); ok {
		extra = NewSet(sf.SecretFlags()...)
	}
	isSecret := func(name string) bool { return secretFlags[name] || extra[name] }
	out := append([]string(nil), p.raw...)
	for i := 1; i < len(out); i++ {
		a := out[i]
		if name, _, hasEq := strings.Cut(a, "="); hasEq && strings.HasPrefix(a, "-") {
			if isSecret(name) {
				out[i] = name + "=" + Redacted
			}
			continue
		}
		if isSecret(a) && i+1 < len(out) && !strings.HasPrefix(out[i+1], "-") {
			out[i+1] = Redacted
			i++
		}
	}
	return out
}

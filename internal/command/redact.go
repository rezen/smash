package command

// Redaction for logs. A command line can carry credentials — curl -H
// 'Authorization: …', mysql -p PASS, --token … — so anything rendered into an
// audit record goes through Redact first. Typed params mark secret fields with
// a `secret:"true"` tag; the generic form redacts the values of well-known
// secret flags, plus any the command declares via SecretFlags.

import (
	"net/url"
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
	out.attached = p.attached.Clone()
	for name, vals := range p.Flags {
		if secretFlags[name] || extra[name] {
			delete(out.attached, name)
		}
		red := make([]string, len(vals))
		for i, v := range vals {
			if v != "" && (secretFlags[name] || extra[name]) {
				v = Redacted
			}
			red[i] = RedactURL(v)
		}
		out.Flags[name] = red
	}
	out.Operands = make([]string, len(p.Operands))
	for i, v := range p.Operands {
		out.Operands[i] = RedactURL(v)
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
	for _, field := range fieldsOf(v.Type()) {
		f := cp.FieldByIndex(field.index)
		switch f.Kind() {
		case reflect.String:
			if field.secret == "true" && f.String() != "" {
				f.SetString(Redacted)
			} else {
				f.SetString(RedactURL(f.String()))
			}
		case reflect.Slice:
			n := f.Len()
			if n == 0 {
				continue
			}
			if f.Type().Elem().Kind() != reflect.String {
				continue
			}
			red := append([]string(nil), f.Interface().([]string)...)
			if field.secret != "" && field.secret != "true" {
				red = redactPairs(red, NewSet(strings.Split(field.secret, ",")...))
			}
			for j := 0; j < n; j++ {
				if field.secret == "true" {
					red[j] = Redacted
				} else {
					red[j] = RedactURL(red[j])
				}
			}
			f.Set(reflect.ValueOf(red))
		}
	}
	return cp.Interface().(Params)
}

// RedactURL removes a URL's complete userinfo, including token-only usernames.
func RedactURL(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.User == nil {
		return s
	}
	u.User = url.User(Redacted)
	return u.String()
}

// RedactResources returns an independent list safe to place in an audit record.
func RedactResources(rs []Resource) []Resource {
	out := make([]Resource, len(rs))
	for i, r := range rs {
		r.Value = RedactURL(r.Value)
		out[i] = r
	}
	return out
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

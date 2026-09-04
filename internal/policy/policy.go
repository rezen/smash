// Package policy reads a whole run's policy — everything the CLI otherwise
// takes as flags, plus the parts that until now were reachable only from Go
// (mocks, emulation, injected headers, extra environment) — from a single YAML
// file.
//
// A file is decoded strictly: an unknown key is an error, so a typo in a
// policy fails loudly instead of silently leaving a gate open. Every section is
// optional and every field is a pointer or a nil-able container, which is what
// lets Apply tell "the user did not say" from "the user said empty" — the
// former keeps the sandbox default, the latter replaces it.
//
// Template writes the commented boilerplate that `smash -init-policy` emits.
package policy

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rezen/smash/internal/sandbox"
)

// File is a policy file. Field order here is the order in Template.
type File struct {
	// Root, Script and Args describe the run itself rather than the policy;
	// the CLI reads them before it builds the Config, so Apply ignores them.
	Root   *string  `yaml:"root"`
	Script string   `yaml:"script"`
	Args   []string `yaml:"args"`

	Strict    *bool     `yaml:"strict"`
	AllowSudo *bool     `yaml:"allow-sudo"`
	Posix     *bool     `yaml:"posix"`
	Timeout   *Duration `yaml:"timeout"`

	Env map[string]string `yaml:"env"`

	Audit     *Audit     `yaml:"audit"`
	Commands  *Commands  `yaml:"commands"`
	Network   *Network   `yaml:"network"`
	Emulation *Emulation `yaml:"emulation"`
	Mocks     []Mock     `yaml:"mocks"`
}

// Audit controls where the audit trail goes and how much of each command's
// stdin/stdout is captured into it.
type Audit struct {
	Path *string `yaml:"path"` // "-" = stderr, "" = off, anything else a file
	Data *int    `yaml:"data"` // bytes of stdin/stdout captured per command
}

// Commands is the command gate: which names run without remark, which are
// blocked despite being unlisted, and which are blocked outright.
type Commands struct {
	Allow     Strings `yaml:"allow"`     // added to the default allow-list
	Disable   Strings `yaml:"disable"`   // blocked outright, even if allowed
	Sensitive Strings `yaml:"sensitive"` // added to the default sensitive list
	// Replace makes Allow and Sensitive replace the defaults instead of
	// widening them. Disable is always additive — it has no default.
	Replace bool `yaml:"replace"`
}

// Network mirrors sandbox.Policy.
type Network struct {
	URLs        Strings           `yaml:"urls"`         // replaces the default allow-list when present
	GitHub      bool              `yaml:"github"`       // also append sandbox.GitHubPrefixes
	GitHosts    Strings           `yaml:"git-hosts"`    // replaces the default forges when present
	Methods     Strings           `yaml:"methods"`      // replaces the default GET/HEAD when present
	MaxResponse *Size             `yaml:"max-response"` // bytes, or a size like "200MiB"
	Timeout     *Duration         `yaml:"timeout"`
	Headers     map[string]string `yaml:"headers"`
}

// Emulation mirrors sandbox.Emulation: a fake target OS for a Linux-only
// installer on a non-Linux host.
type Emulation struct {
	UnameOS   string            `yaml:"uname-os"`
	UnameArch string            `yaml:"uname-arch"`
	Files     map[string]string `yaml:"files"`
}

// Mock is one canned response: a matcher plus what the command should say.
type Mock struct {
	Match  Match  `yaml:"match"`
	Stdout string `yaml:"stdout"`
	Stderr string `yaml:"stderr"`
	Exit   int    `yaml:"exit"`
}

// Match selects the invocations a Mock answers. Every field that is set must
// hold, so `name` plus `resource` is "this command reaching that URL". The
// dynamic matchers (sandbox.MatchFunc, Mock.Respond) are Go-only and have no
// YAML spelling.
type Match struct {
	Name     Strings   `yaml:"name"`     // command name, or any of several
	Args     Strings   `yaml:"args"`     // the exact argv
	Prefix   Strings   `yaml:"prefix"`   // an argv that starts with these
	Glob     string    `yaml:"glob"`     // "*"/"?" glob over the whole command line
	Resource *Resource `yaml:"resource"` // a touched resource of a kind matching a glob
}

// Resource is the `resource:` matcher: a resource kind (url, path, host, …)
// whose value matches a glob.
type Resource struct {
	Kind  string `yaml:"kind"`
	Value string `yaml:"value"`
}

// Load reads and decodes a policy file. Unknown keys are rejected.
func Load(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b, path)
}

// Parse decodes a policy from YAML. name labels errors.
func Parse(b []byte, name string) (*File, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true) // a mistyped key is a silently missing rule; refuse it
	var f File
	if err := dec.Decode(&f); err != nil {
		if err.Error() == "EOF" { // an empty file is a policy that says nothing
			return &File{}, nil
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return &f, nil
}

func (f *File) validate() error {
	for i, m := range f.Mocks {
		if m.Match.empty() {
			return fmt.Errorf("mocks[%d]: needs at least one of name, args, prefix, glob, resource", i)
		}
		if r := m.Match.Resource; r != nil && (r.Kind == "" || r.Value == "") {
			return fmt.Errorf("mocks[%d].match.resource: needs both kind and value", i)
		}
	}
	return nil
}

func (m Match) empty() bool {
	return len(m.Name) == 0 && len(m.Args) == 0 && len(m.Prefix) == 0 && m.Glob == "" && m.Resource == nil
}

// Apply layers the policy onto cfg, which the caller has already built with
// sandbox.NewConfig — so an absent section leaves the sandbox default in
// place. It does not read Root, Script, Args or Env: those shape the Config
// before it exists, and the CLI reads them itself.
func (f *File) Apply(cfg *sandbox.Config) error {
	if f == nil {
		return nil
	}
	setBool(&cfg.Strict, f.Strict)
	setBool(&cfg.AllowSudo, f.AllowSudo)
	setBool(&cfg.Posix, f.Posix)
	if f.Timeout != nil {
		cfg.Timeout = time.Duration(*f.Timeout)
	}
	if c := f.Commands; c != nil {
		if c.Replace {
			cfg.Allowed = nil
			cfg.Sensitive = nil
		}
		if len(c.Allow) > 0 || c.Replace {
			cfg.Allowed = cfg.Allowed.With(c.Allow...)
		}
		if len(c.Sensitive) > 0 || c.Replace {
			cfg.Sensitive = cfg.Sensitive.With(c.Sensitive...)
		}
		if len(c.Disable) > 0 {
			cfg.Disable(c.Disable...)
		}
	}
	if n := f.Network; n != nil {
		if n.URLs != nil {
			cfg.Network.AllowedPrefixes = n.URLs
		}
		if n.GitHub {
			cfg.Network.AllowedPrefixes = append(cfg.Network.AllowedPrefixes, sandbox.GitHubPrefixes()...)
		}
		if n.GitHosts != nil {
			cfg.Network.GitHosts = n.GitHosts
		}
		if n.Methods != nil {
			cfg.Network.AllowedMethods = map[string]bool{}
			for _, m := range n.Methods {
				cfg.Network.AllowedMethods[strings.ToUpper(m)] = true
			}
		}
		if n.MaxResponse != nil {
			cfg.Network.MaxResponse = int64(*n.MaxResponse)
		}
		if n.Timeout != nil {
			cfg.Network.Timeout = time.Duration(*n.Timeout)
		}
		if len(n.Headers) > 0 {
			if cfg.Network.InjectHeaders == nil {
				cfg.Network.InjectHeaders = map[string]string{}
			}
			for k, v := range n.Headers {
				cfg.Network.InjectHeaders[k] = v
			}
		}
	}
	if e := f.Emulation; e != nil && (e.UnameOS != "" || len(e.Files) > 0) {
		cfg.Emulation = sandbox.Emulation{UnameOS: e.UnameOS, UnameArch: e.UnameArch, Files: e.Files}
	}
	for i, m := range f.Mocks {
		match, err := m.Match.matcher()
		if err != nil {
			return fmt.Errorf("mocks[%d]: %w", i, err)
		}
		cfg.Mock(match, m.Stdout, m.Stderr, m.Exit)
	}
	return nil
}

// matcher builds the sandbox.Matcher for one `match:` block. Several fields
// compose with And, so the block reads as one conjunction.
func (m Match) matcher() (sandbox.Matcher, error) {
	var ms []sandbox.Matcher
	if len(m.Name) > 0 {
		ms = append(ms, sandbox.MatchName(m.Name...))
	}
	if len(m.Args) > 0 {
		ms = append(ms, sandbox.MatchArgs(m.Args...))
	}
	if len(m.Prefix) > 0 {
		ms = append(ms, sandbox.MatchPrefix(m.Prefix...))
	}
	if m.Glob != "" {
		ms = append(ms, sandbox.MatchGlob(m.Glob))
	}
	if m.Resource != nil {
		ms = append(ms, sandbox.MatchResource(m.Resource.Kind, m.Resource.Value))
	}
	if len(ms) == 0 {
		return nil, fmt.Errorf("needs at least one of name, args, prefix, glob, resource")
	}
	return ms[0].And(ms[1:]...), nil
}

// EnvPairs returns the policy's env: section as the "NAME=value" pairs
// expand.ListEnviron takes, sorted for a stable result. Appending them to the
// sandbox's own pairs makes them win: ListEnviron sorts stably and keeps the
// last of a duplicate name.
func (f *File) EnvPairs() []string {
	if f == nil || len(f.Env) == 0 {
		return nil
	}
	pairs := make([]string, 0, len(f.Env))
	for k, v := range f.Env {
		pairs = append(pairs, k+"="+v)
	}
	slices.Sort(pairs)
	return pairs
}

func setBool(dst *bool, src *bool) {
	if src != nil {
		*dst = *src
	}
}

// Strings is a list of strings that also accepts a bare scalar, so
// `name: curl` and `name: [curl, wget]` both work.
type Strings []string

func (s *Strings) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var one string
		if err := n.Decode(&one); err != nil {
			return err
		}
		*s = Strings{one}
		return nil
	}
	var many []string
	if err := n.Decode(&many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Duration is a time.Duration written the Go way ("60s", "2m", "1h30m").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: duration must be a string like \"60s\" or \"2m\"", n.Line)
	}
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// Size is a byte count, written plainly (209715200) or with a unit
// ("200MiB", "1GB"). Binary units are powers of 1024, decimal ones of 1000.
type Size int64

var sizeUnits = []struct {
	suffix string
	mul    int64
}{
	{"KIB", 1 << 10}, {"MIB", 1 << 20}, {"GIB", 1 << 30},
	{"KB", 1000}, {"MB", 1000 * 1000}, {"GB", 1000 * 1000 * 1000},
	{"K", 1 << 10}, {"M", 1 << 20}, {"G", 1 << 30},
	{"B", 1},
}

func (z *Size) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode {
		return fmt.Errorf("line %d: size must be a byte count or a string like \"200MiB\"", n.Line)
	}
	v, err := parseSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*z = Size(v)
	return nil
}

func parseSize(raw string) (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(raw))
	for _, u := range sizeUnits {
		num, ok := strings.CutSuffix(s, u.suffix)
		if !ok {
			continue
		}
		num = strings.TrimSpace(num)
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			break
		}
		if f < 0 {
			return 0, fmt.Errorf("size %q is negative", raw)
		}
		return int64(f * float64(u.mul)), nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("bad size %q: want a byte count or a value like \"200MiB\"", raw)
	}
	return v, nil
}

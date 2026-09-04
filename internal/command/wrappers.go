package command

// Wrapper commands prefix another command: `sudo apt-get …`, `env FOO=bar curl …`,
// `timeout 5 openssl s_client …`. A name-based guard that only inspects args[0]
// is fooled by every one — the real command slips past the allow-list, the
// curl/wget interception, and the egress guard. Unwrap peels them so every
// guard enforces on the real command.
//
// Wrapper semantics (privilege, timeout, env vars, xargs iteration) are dropped:
// in a sandbox, confining the real command matters more than preserving the
// wrapper's behaviour. Stripping sudo/doas is itself a feature — the inner
// command runs confined instead of actually escalating.

import "strings"

// PrefixWrapper describes a wrapper whose inner command follows its own flags:
// skip the flags (and their values), optionally NAME=value assignments (env),
// and SkipPositionals leading operands (timeout's DURATION).
type PrefixWrapper struct {
	Aliases         []string
	Spec            Spec
	SkipPositionals int
	Assignments     bool
}

func (w PrefixWrapper) Names() []string                { return w.Aliases }
func (w PrefixWrapper) Parse(a []string) ParsedCommand { return w.Spec.Parse(a) }
func (w PrefixWrapper) Unwrap(a []string) []string {
	return innerAfter(a, w.Spec.ValueFlags, w.SkipPositionals, w.Assignments)
}

// prefix is shorthand for a PrefixWrapper with only value flags.
func prefix(name string, valueFlags ...string) PrefixWrapper {
	return PrefixWrapper{Aliases: []string{name}, Spec: Spec{ValueFlags: NewSet(valueFlags...)}}
}

var wrapperCommands = []Command{
	Sudo{PrefixWrapper{Aliases: []string{"sudo", "doas"},
		Spec: Spec{ValueFlags: NewSet("-u", "-g", "-U", "-h", "-p", "-C", "-r", "-t")}}},
	PrefixWrapper{Aliases: []string{"env"}, Spec: Spec{ValueFlags: NewSet("-u")}, Assignments: true},
	PrefixWrapper{Aliases: []string{"timeout"},
		Spec: Spec{ValueFlags: NewSet("-s", "--signal", "-k", "--kill-after")}, SkipPositionals: 1},
	Xargs{},
	prefix("nice", "-n"),
	prefix("ionice", "-c", "-n", "-p"),
	prefix("nohup"),
	prefix("setsid"),
	prefix("stdbuf", "-i", "-o", "-e"),
	prefix("command"),
	prefix("time", "-o", "-f", "--format", "--output"),
	prefix("watch", "-n", "--interval", "-d", "--differences"),
	prefix("sshpass", "-p", "-f", "-d", "-P"),
}

// Sudo is the privilege wrapper (sudo/doas). Besides prefixing a command it
// has credential-probe modes that run nothing: `sudo -v` (validate/refresh the
// timestamp), `sudo -l [CMD]` (list, or check whether CMD is permitted) and
// `sudo -K` (drop the timestamp). Installers gate on them (`sudo -n -l mkdir`
// in Homebrew's have_sudo_access). Unwrap returns no inner command for a probe,
// so it reaches the sandbox as `sudo` itself — where the allow-list blocks it,
// or Config.AllowSudo answers it.
type Sudo struct{ PrefixWrapper }

// sudoProbeLong are the long-form flags that make sudo a probe; sudoProbeShort
// their single-letter forms, which may appear in a cluster (`-nv`, `-nl`).
var (
	sudoProbeLong  = NewSet("--validate", "--list", "--remove-timestamp", "--version")
	sudoProbeShort = "vlKV"
)

func (w Sudo) Unwrap(a []string) []string {
	for i := 1; i < len(a); i++ {
		s := a[i]
		switch {
		case s == "--" || !strings.HasPrefix(s, "-") || s == "-":
			return w.PrefixWrapper.Unwrap(a)
		case strings.HasPrefix(s, "--"):
			if sudoProbeLong[s] {
				return nil
			}
		case strings.ContainsAny(s[1:], sudoProbeShort):
			return nil
		}
		if w.Spec.ValueFlags[s] {
			i++ // skip the value
		}
	}
	return nil
}

// Xargs is its own type: unlike a plain prefix wrapper it feeds stdin items as
// arguments to the inner command (dropped here — confining the command name is
// what matters), and with NO command it defaults to running echo. Note `-i` is
// deliberately NOT a value flag: its replace-string is optional and attached
// (`-i{}`), so treating it as consuming the next arg would swallow the command
// (`xargs -i rm` → inner `rm`, not `-i`'s value).
type Xargs struct{}

var xargsSpec = Spec{ValueFlags: NewSet("-n", "-P", "-I", "-d", "-E", "-s", "-L", "-a",
	"--max-args", "--max-procs", "--replace", "--delimiter", "--max-lines", "--arg-file")}

func (Xargs) Names() []string                { return []string{"xargs"} }
func (Xargs) Parse(a []string) ParsedCommand { return xargsSpec.Parse(a) }
func (Xargs) Unwrap(a []string) []string {
	if inner := innerAfter(a, xargsSpec.ValueFlags, 0, false); len(inner) > 0 {
		return inner
	}
	return []string{"echo"} // xargs with no command runs echo
}

// innerAfter finds where a wrapper's inner command begins: skip the wrapper's
// flags (+ their values), env-style assignments, and skipPos leading positionals
// (e.g. timeout's DURATION). Returns the inner argv, or nil if none follows.
func innerAfter(args []string, valueFlags Set, skipPos int, assignments bool) []string {
	for i := 1; i < len(args); {
		a := args[i]
		switch {
		case a == "--":
			return args[i+1:]
		case a != "-" && strings.HasPrefix(a, "-"):
			if _, _, hasEq := strings.Cut(a, "="); hasEq {
				i++
				continue
			}
			i++
			if valueFlags[a] {
				i++ // consume the separate value
			}
		case assignments && isAssignment(a):
			i++
		default:
			i += skipPos
			if i < len(args) {
				return args[i:]
			}
			return nil
		}
	}
	return nil
}

// isAssignment reports whether s looks like NAME=value.
func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range s[:eq] {
		if r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// Unwrap peels wrapper commands (via the Wrapper interface) and returns the
// wrapper names seen plus the innermost real command argv. A wrapper with no
// inner command is treated as a normal command, not a wrapper.
func Unwrap(args []string) (chain []string, inner []string) {
	inner = args
	for len(inner) > 0 {
		w, ok := Lookup(inner[0]).(Wrapper)
		if !ok {
			break
		}
		rest := w.Unwrap(inner)
		if len(rest) == 0 {
			break
		}
		chain = append(chain, baseName(inner[0]))
		inner = rest
	}
	return chain, inner
}

package command

import "strings"

// Builtins: the safe local tools the sandbox knows — text/file/archive utilities
// with no network reach. They are Commands like everything else, marked Builtin
// so allow-lists can be derived from the registry (BuiltinNames) instead of a
// hand-kept string list. The common text tools get concrete types with real
// flag specs (so their -f/-e/-C values parse); the long tail uses Tool.
// Find is the one that also implements Wrapper (its -exec runs commands).

// Tool is a safe local command that needs no special parsing beyond a Spec.
// For audit logs, OperandKind names what its operands are ("path" for filters;
// "" logs them as plain operands) and Stdin says it reads a pipe when given
// no operand (cat, sort, sha256sum, …).
type Tool struct {
	Aliases     []string
	Spec        Spec
	OperandKind string
	Stdin       bool
}

func (t Tool) Names() []string                { return t.Aliases }
func (t Tool) Parse(a []string) ParsedCommand { return t.Spec.Parse(a) }
func (Tool) builtin()                         {}

// tool is shorthand for a Tool with no value flags.
func tool(names ...string) Tool { return Tool{Aliases: names} }

// filter is a Tool that reads the files it is given, or stdin.
func filter(names ...string) Tool { return Tool{Aliases: names, OperandKind: "path", Stdin: true} }

var grepSpec = Spec{ClusterShort: true, ValueFlags: NewSet(
	"-e", "-f", "-m", "-A", "-B", "-C", "-d", "--regexp", "--file", "--max-count")}

type Grep struct{}

func (Grep) Names() []string                { return []string{"grep", "egrep", "fgrep", "rg"} }
func (Grep) Parse(a []string) ParsedCommand { return grepSpec.Parse(a) }
func (Grep) builtin()                       {}

// -i is optional-attached (`-i.bak`), so it is NOT a separate-value flag.
var sedSpec = Spec{ClusterShort: true, ValueFlags: NewSet("-e", "-f", "--expression", "--file"), AttachedValue: NewSet("-i")}

type Sed struct{}

func (Sed) Names() []string                { return []string{"sed"} }
func (Sed) Parse(a []string) ParsedCommand { return sedSpec.Parse(a) }
func (Sed) builtin()                       {}

var awkSpec = Spec{ValueFlags: NewSet("-F", "-v", "-f", "--field-separator", "--assign")}

type Awk struct{}

func (Awk) Names() []string                { return []string{"awk", "gawk", "mawk"} }
func (Awk) Parse(a []string) ParsedCommand { return awkSpec.Parse(a) }
func (Awk) builtin()                       {}

var tarSpec = Spec{ClusterShort: true, ValueFlags: NewSet("-f", "-C", "-T", "--file", "--directory", "--strip-components", "--exclude")}

type Tar struct{}

func (Tar) Names() []string { return []string{"tar", "gtar"} }

// Parse accepts tar's old-style first operand (`tar xf a.tgz`, `tar czvf …`):
// a bare letter bundle in position one is the same as a dashed cluster.
func (Tar) Parse(a []string) ParsedCommand {
	if len(a) > 1 && isTarOldStyleBundle(a[1]) {
		a = append([]string{a[0], "-" + a[1]}, a[2:]...)
	}
	return tarSpec.Parse(a)
}

func isTarOldStyleBundle(s string) bool {
	if s == "" || strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("AcdrtuxjJzZvfCOpPkmhoswaWlnHTX", r) {
			return false
		}
	}
	return true
}
func (Tar) builtin() {}

// Base64 is an offline encoder/decoder. It is modelled (rather than a plain
// Tool) because `… | base64 -d | sh` is the classic way to smuggle an obfuscated
// payload past a reader, so a guard may want to see the Decode bit. GNU flags,
// plus BSD's -D as a decode alias.
type Base64 struct{}

func (Base64) Names() []string                { return []string{"base64"} }
func (Base64) Parse(a []string) ParsedCommand { return base64Spec.Parse(a) }
func (Base64) Params(p ParsedCommand) Params  { return base64ParamsFrom(p) }
func (Base64) builtin()                       {}

// Find is a safe listing tool that can ALSO run commands via
// -exec/-execdir/-ok/-okdir — so it's a Builtin that also implements Wrapper.
// Plain `find` just lists; when it execs, the inner command is peeled out and
// re-enforced by the sandbox (`find / -exec rm {} \;` → the guard sees `rm`).
type Find struct{}

func (Find) Names() []string                { return []string{"find"} }
func (Find) Parse(a []string) ParsedCommand { return Spec{}.Parse(a) }
func (Find) builtin()                       {}
func (Find) Params(p ParsedCommand) Params  { return findParamsFrom(p.raw) }
func (Find) Unwrap(args []string) []string  { return findParamsFrom(args).ExecArgv() }

// builtinCommands is the registry of safe local tools. curl/wget/openssl/ssh/…
// are deliberately NOT here — those are network-capable and gated separately.
var builtinCommands = []Builtin{
	Grep{}, Sed{}, Awk{}, Tar{}, Find{}, Base64{},
	Chmod{}, Chown{}, Chgrp{}, Chattr{}, Setfacl{}, Chflags{}, Chcon{}, Xattr{}, InstallCommand{},
	// os / arch / identity
	tool("uname", "ldd", "getent", "id", "whoami", "which", "ps"),
	// filesystem: rm/mv/cp/mkdir/ln/mktemp/tee/unzip/gzip/dd are FileOperators in fileops.go
	tool("readlink"),
	// permissions: the mutating ones are PathMutators in perms.go
	tool("getfacl"), tool("lsattr"),
	// text: filters read their file operands or a pipe
	filter("cat"), filter("cut"), filter("tr"), filter("head"), filter("tail"),
	filter("sort"), filter("wc"), tool("printf"), tool("echo"), tool("dirname"),
	tool("basename"),
	// checksums / crypto tools (offline)
	filter("sha256sum"), filter("sha512sum"), filter("shasum"), filter("b2sum"),
	// gpg lives in nettools.go: a Builtin that is also Networked (keyservers).
	// misc. NOTE: `env` is NOT here — it's a Wrapper; the Registry would reject
	// the duplicate name anyway, so `env … curl` can never run unconfined.
	tool("sleep"), tool("date"), tool("clear"),
}

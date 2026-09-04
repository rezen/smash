package command

// Permission commands: the tools that change a file's mode, owner, group,
// attributes or ACLs. Each is a Builtin (offline, allow-listable) with tagged
// params AND a PathMutator, so a guard can see exactly which paths an
// invocation touches and whether it recurses.
//
// Two of them (chmod, chattr) accept a MODE that starts with "-" (`chmod -x f`,
// `chattr -i f`), which the generic parser reads as a flag. modeFromFlags
// recovers it: a flag that matches the command's mode grammar is the mode, and
// every operand is then a path.

import (
	"regexp"
	"sort"
	"strings"
)

// modeFromFlags returns the first flag name matching re, or "".
func modeFromFlags(p ParsedCommand, re *regexp.Regexp) string {
	names := make([]string, 0, len(p.Flags))
	for n := range p.Flags {
		if re.MatchString(n) {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return names[0]
}

// Chmod --------------------------------------------------------------------

type ChmodParams struct {
	Recursive bool     `flag:"-R,--recursive"`
	Verbose   bool     `flag:"-v,--verbose"`
	Changes   bool     `flag:"-c,--changes"`
	Silent    bool     `flag:"-f,--silent,--quiet"`
	Reference string   `flag:"--reference"`
	Mode      string   `operand:"first" resource:"mode,apply"` // e.g. 755, u+x, -x; empty with --reference
	Paths     []string `operand:"rest" resource:"path,modify"`
}

// chmodModeRE: symbolic modes that start with "-" (-x, -rwx, -go+w is not
// supported), or a leading-dash octal.
var chmodModeRE = regexp.MustCompile(`^-([ugoa]*[rwxXst]+|[0-7]{3,4})$`)

var chmodSpec = specOf(ChmodParams{}, false, "--preserve-root", "--no-preserve-root")

type Chmod struct{}

func (Chmod) Names() []string                { return []string{"chmod"} }
func (Chmod) Parse(a []string) ParsedCommand { return chmodSpec.Parse(a) }
func (Chmod) Params(p ParsedCommand) Params  { return chmodParamsFrom(p) }
func (Chmod) builtin()                       {}
func (Chmod) Targets(p ParsedCommand) ([]string, bool) {
	c := chmodParamsFrom(p)
	return c.Paths, c.Recursive
}

func chmodParamsFrom(p ParsedCommand) (c ChmodParams) {
	bind(p, &c)
	if c.Reference != "" { // no MODE operand: every operand is a path
		c.Mode, c.Paths = "", append([]string(nil), p.Operands...)
	} else if m := modeFromFlags(p, chmodModeRE); m != "" {
		c.Mode, c.Paths = m, append([]string(nil), p.Operands...)
	}
	return c
}
func (c ChmodParams) Args() []string { return render("chmod", c, false) }
func (c ChmodParams) String() string { return JoinArgs(c.Args()) }

// Chown / Chgrp ------------------------------------------------------------

type ChownParams struct {
	Recursive     bool     `flag:"-R,--recursive"`
	NoDereference bool     `flag:"-h,--no-dereference"`
	Verbose       bool     `flag:"-v,--verbose"`
	Changes       bool     `flag:"-c,--changes"`
	Silent        bool     `flag:"-f,--silent,--quiet"`
	From          string   `flag:"--from"`
	Reference     string   `flag:"--reference"`
	Owner         string   `operand:"first" resource:"owner,apply"` // USER, USER:GROUP, :GROUP (or USER.GROUP)
	Paths         []string `operand:"rest" resource:"path,modify"`
}

// User and Group split the OWNER operand.
func (c ChownParams) User() string  { u, _ := splitOwner(c.Owner); return u }
func (c ChownParams) Group() string { _, g := splitOwner(c.Owner); return g }

func splitOwner(owner string) (user, group string) {
	if u, g, ok := strings.Cut(owner, ":"); ok {
		return u, g
	}
	if u, g, ok := strings.Cut(owner, "."); ok {
		return u, g
	}
	return owner, ""
}

var chownSpec = specOf(ChownParams{}, true,
	"--preserve-root", "--no-preserve-root", "--dereference", "-H", "-L", "-P")

type Chown struct{}

func (Chown) Names() []string                { return []string{"chown"} }
func (Chown) Parse(a []string) ParsedCommand { return chownSpec.Parse(a) }
func (Chown) Params(p ParsedCommand) Params  { return chownParamsFrom(p) }
func (Chown) builtin()                       {}
func (Chown) Targets(p ParsedCommand) ([]string, bool) {
	c := chownParamsFrom(p)
	return c.Paths, c.Recursive
}

func chownParamsFrom(p ParsedCommand) (c ChownParams) {
	bind(p, &c)
	if c.Reference != "" {
		c.Owner, c.Paths = "", append([]string(nil), p.Operands...)
	}
	return c
}
func (c ChownParams) Args() []string { return render("chown", c, true) }
func (c ChownParams) String() string { return JoinArgs(c.Args()) }

type ChgrpParams struct {
	Recursive     bool     `flag:"-R,--recursive"`
	NoDereference bool     `flag:"-h,--no-dereference"`
	Verbose       bool     `flag:"-v,--verbose"`
	Changes       bool     `flag:"-c,--changes"`
	Silent        bool     `flag:"-f,--silent,--quiet"`
	Reference     string   `flag:"--reference"`
	Group         string   `operand:"first" resource:"group,apply"`
	Paths         []string `operand:"rest" resource:"path,modify"`
}

var chgrpSpec = specOf(ChgrpParams{}, true,
	"--preserve-root", "--no-preserve-root", "--dereference", "-H", "-L", "-P")

type Chgrp struct{}

func (Chgrp) Names() []string                { return []string{"chgrp"} }
func (Chgrp) Parse(a []string) ParsedCommand { return chgrpSpec.Parse(a) }
func (Chgrp) Params(p ParsedCommand) Params  { return chgrpParamsFrom(p) }
func (Chgrp) builtin()                       {}
func (Chgrp) Targets(p ParsedCommand) ([]string, bool) {
	c := chgrpParamsFrom(p)
	return c.Paths, c.Recursive
}

func chgrpParamsFrom(p ParsedCommand) (c ChgrpParams) {
	bind(p, &c)
	if c.Reference != "" {
		c.Group, c.Paths = "", append([]string(nil), p.Operands...)
	}
	return c
}
func (c ChgrpParams) Args() []string { return render("chgrp", c, true) }
func (c ChgrpParams) String() string { return JoinArgs(c.Args()) }

// Chattr (Linux ext attributes) --------------------------------------------

type ChattrParams struct {
	Recursive bool     `flag:"-R"`
	Verbose   bool     `flag:"-V"`
	Silent    bool     `flag:"-f"`
	Version   string   `flag:"-v"`
	Project   string   `flag:"-p"`
	Mode      string   `operand:"first" resource:"attributes,apply"` // +i, -i, =a, +aA…
	Paths     []string `operand:"rest" resource:"path,modify"`
}

// chattrModeRE: attribute letters after a leading "-" (none of chattr's real
// flags -R -V -f -v -p are attribute letters).
var chattrModeRE = regexp.MustCompile(`^-[aAcCdDeFijmPsStTux]+$`)

var chattrSpec = specOf(ChattrParams{}, false)

type Chattr struct{}

func (Chattr) Names() []string                { return []string{"chattr"} }
func (Chattr) Parse(a []string) ParsedCommand { return chattrSpec.Parse(a) }
func (Chattr) Params(p ParsedCommand) Params  { return chattrParamsFrom(p) }
func (Chattr) builtin()                       {}
func (Chattr) Targets(p ParsedCommand) ([]string, bool) {
	c := chattrParamsFrom(p)
	return c.Paths, c.Recursive
}

func chattrParamsFrom(p ParsedCommand) (c ChattrParams) {
	bind(p, &c)
	if m := modeFromFlags(p, chattrModeRE); m != "" {
		c.Mode, c.Paths = m, append([]string(nil), p.Operands...)
	}
	return c
}
func (c ChattrParams) Args() []string { return render("chattr", c, false) }
func (c ChattrParams) String() string { return JoinArgs(c.Args()) }

// Xattr (macOS extended attributes) ----------------------------------------
//
// The operand layout depends on the mode: `-d NAME paths…`, `-w NAME VALUE
// paths…`, `-p NAME paths…`, and `-c`/`-l` take only paths. Installers use
// `xattr -dr com.apple.quarantine DIR` to un-quarantine what they unpacked, so
// that step shows up in the audit as an attribute delete on the paths.

type XattrParams struct {
	Recursive bool `flag:"-r"`
	Symlink   bool `flag:"-s"`
	Verbose   bool `flag:"-v"`
	Hex       bool `flag:"-x"`
	List      bool `flag:"-l"`
	Print     bool `flag:"-p"`
	Delete    bool `flag:"-d"`
	Write     bool `flag:"-w"`
	Clear     bool `flag:"-c"`
	Name      string
	Value     string
	Paths     []string
}

var xattrSpec = specOf(XattrParams{}, true)

type Xattr struct{}

func (Xattr) Names() []string                { return []string{"xattr"} }
func (Xattr) Parse(a []string) ParsedCommand { return xattrSpec.Parse(a) }
func (Xattr) Params(p ParsedCommand) Params  { return xattrParamsFrom(p) }
func (Xattr) builtin()                       {}
func (Xattr) Targets(p ParsedCommand) ([]string, bool) {
	x := xattrParamsFrom(p)
	if !x.mutates() {
		return nil, false
	}
	return x.Paths, x.Recursive
}
func (Xattr) Resources(p ParsedCommand) []Resource {
	x := xattrParamsFrom(p)
	var out []Resource
	switch {
	case x.Delete:
		out = append(out, Resource{Kind: "attribute", Action: "delete", Value: x.Name})
	case x.Write:
		out = append(out, Resource{Kind: "attribute", Action: "write", Value: x.Name + "=" + x.Value})
	case x.Clear:
		out = append(out, Resource{Kind: "attribute", Action: "clear", Value: "*"})
	case x.Print:
		out = append(out, Resource{Kind: "attribute", Action: "read", Value: x.Name})
	}
	action := "read"
	if x.mutates() {
		action = "modify"
	}
	for _, path := range x.Paths {
		out = append(out, Resource{Kind: "path", Action: action, Value: path})
	}
	return out
}

func (x XattrParams) mutates() bool { return x.Delete || x.Write || x.Clear }

func xattrParamsFrom(p ParsedCommand) (x XattrParams) {
	bind(p, &x)
	ops := p.Operands
	take := func() string {
		if len(ops) == 0 {
			return ""
		}
		v := ops[0]
		ops = ops[1:]
		return v
	}
	switch {
	case x.Write:
		x.Name, x.Value = take(), take()
	case x.Delete || x.Print:
		x.Name = take()
	}
	x.Paths = append([]string(nil), ops...)
	return x
}
func (x XattrParams) Args() []string {
	args := render("xattr", x, true)
	switch {
	case x.Write:
		args = append(args, x.Name, x.Value)
	case x.Delete || x.Print:
		args = append(args, x.Name)
	}
	return append(args, x.Paths...)
}
func (x XattrParams) String() string { return JoinArgs(x.Args()) }

// Setfacl ------------------------------------------------------------------

type SetfaclParams struct {
	Recursive     bool     `flag:"-R,--recursive"`
	Default       bool     `flag:"-d,--default"`
	RemoveAll     bool     `flag:"-b,--remove-all"`
	RemoveDefault bool     `flag:"-k,--remove-default"`
	NoMask        bool     `flag:"-n,--no-mask"`
	Modify        []string `flag:"-m,--modify" resource:"acl,add"`
	Remove        []string `flag:"-x,--remove" resource:"acl,remove"`
	Set           []string `flag:"--set" resource:"acl,set"`
	ModifyFile    string   `flag:"-M,--modify-file"`
	RemoveFile    string   `flag:"-X,--remove-file"`
	SetFile       string   `flag:"--set-file"`
	Restore       string   `flag:"--restore"`
	Paths         []string `operand:"all" resource:"path,modify"`
}

var setfaclSpec = specOf(SetfaclParams{}, true, "--mask", "-L", "-P", "-H")

type Setfacl struct{}

func (Setfacl) Names() []string                { return []string{"setfacl"} }
func (Setfacl) Parse(a []string) ParsedCommand { return setfaclSpec.Parse(a) }
func (Setfacl) Params(p ParsedCommand) Params  { return setfaclParamsFrom(p) }
func (Setfacl) builtin()                       {}
func (Setfacl) Targets(p ParsedCommand) ([]string, bool) {
	s := setfaclParamsFrom(p)
	return s.Paths, s.Recursive
}

func setfaclParamsFrom(p ParsedCommand) (s SetfaclParams) { bind(p, &s); return s }
func (s SetfaclParams) Args() []string                    { return render("setfacl", s, true) }
func (s SetfaclParams) String() string                    { return JoinArgs(s.Args()) }

// Chflags (BSD/macOS) ------------------------------------------------------

type ChflagsParams struct {
	Recursive bool     `flag:"-R"`
	NoFollow  bool     `flag:"-h"`
	Verbose   bool     `flag:"-v"`
	Silent    bool     `flag:"-f"`
	Flags     string   `operand:"first" resource:"flags,apply"` // e.g. nouchg, hidden, schg
	Paths     []string `operand:"rest" resource:"path,modify"`
}

var chflagsSpec = specOf(ChflagsParams{}, true, "-H", "-L", "-P")

type Chflags struct{}

func (Chflags) Names() []string                { return []string{"chflags"} }
func (Chflags) Parse(a []string) ParsedCommand { return chflagsSpec.Parse(a) }
func (Chflags) Params(p ParsedCommand) Params  { return chflagsParamsFrom(p) }
func (Chflags) builtin()                       {}
func (Chflags) Targets(p ParsedCommand) ([]string, bool) {
	c := chflagsParamsFrom(p)
	return c.Paths, c.Recursive
}

func chflagsParamsFrom(p ParsedCommand) (c ChflagsParams) { bind(p, &c); return c }
func (c ChflagsParams) Args() []string                    { return render("chflags", c, true) }
func (c ChflagsParams) String() string                    { return JoinArgs(c.Args()) }

// Chcon (SELinux) ----------------------------------------------------------

type ChconParams struct {
	Recursive     bool     `flag:"-R,--recursive"`
	NoDereference bool     `flag:"-h,--no-dereference"`
	Verbose       bool     `flag:"-v,--verbose"`
	User          string   `flag:"-u,--user"`
	Role          string   `flag:"-r,--role"`
	Type          string   `flag:"-t,--type"`
	Range         string   `flag:"-l,--range"`
	Reference     string   `flag:"--reference"`
	Context       string   `operand:"first" resource:"context,apply"` // full context, unless any of -u/-r/-t/-l/--reference is given
	Paths         []string `operand:"rest" resource:"path,modify"`
}

var chconSpec = specOf(ChconParams{}, true, "--preserve-root", "--no-preserve-root", "-H", "-L", "-P")

type Chcon struct{}

func (Chcon) Names() []string                { return []string{"chcon"} }
func (Chcon) Parse(a []string) ParsedCommand { return chconSpec.Parse(a) }
func (Chcon) Params(p ParsedCommand) Params  { return chconParamsFrom(p) }
func (Chcon) builtin()                       {}
func (Chcon) Targets(p ParsedCommand) ([]string, bool) {
	c := chconParamsFrom(p)
	return c.Paths, c.Recursive
}

func chconParamsFrom(p ParsedCommand) (c ChconParams) {
	bind(p, &c)
	if c.User != "" || c.Role != "" || c.Type != "" || c.Range != "" || c.Reference != "" {
		c.Context, c.Paths = "", append([]string(nil), p.Operands...)
	}
	return c
}
func (c ChconParams) Args() []string { return render("chcon", c, true) }
func (c ChconParams) String() string { return JoinArgs(c.Args()) }

// InstallCommand ------------------------------------------------------------------

// InstallCommand is coreutils `install`: it copies files AND sets their mode/owner/group in one step, which is
// how most install scripts place binaries. Its targets are what it writes:
// the DEST operand, every operand with -d, or -t DIR.
type InstallParams struct {
	Directory bool     `flag:"-d,--directory"`
	Mode      string   `flag:"-m,--mode"`
	Owner     string   `flag:"-o,--owner"`
	Group     string   `flag:"-g,--group"`
	TargetDir string   `flag:"-t,--target-directory"`
	Strip     bool     `flag:"-s,--strip"`
	Preserve  bool     `flag:"-p,--preserve-timestamps"`
	Verbose   bool     `flag:"-v,--verbose"`
	Operands  []string `operand:"all"` // SRC… DEST, or DIRECTORY… with -d
}

var installSpec = specOf(InstallParams{}, true,
	"-S", "--suffix", "--backup", "--strip-program", "-C", "-D", "-T", "-b", "-c", "--context", "-Z")

type InstallCommand struct{}

func (InstallCommand) Names() []string                { return []string{"install", "ginstall"} }
func (InstallCommand) Parse(a []string) ParsedCommand { return installSpec.Parse(a) }
func (InstallCommand) Params(p ParsedCommand) Params  { return installParamsFrom(p) }
func (InstallCommand) builtin()                       {}
func (InstallCommand) Targets(p ParsedCommand) ([]string, bool) {
	return installParamsFrom(p).Targets(), false
}

func installParamsFrom(p ParsedCommand) (i InstallParams) { bind(p, &i); return i }
func (i InstallParams) Args() []string                    { return render("install", i, true) }
func (i InstallParams) String() string                    { return JoinArgs(i.Args()) }

// Targets returns the paths install creates or overwrites.
func (i InstallParams) Targets() []string {
	switch {
	case i.TargetDir != "":
		return []string{i.TargetDir}
	case i.Directory:
		return i.Operands
	case len(i.Operands) >= 2:
		return []string{i.Operands[len(i.Operands)-1]}
	}
	return nil
}

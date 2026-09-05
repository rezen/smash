package command

// Typed, reversible parameters. Every ParsedCommand can render itself back to a
// command line (String), and the relevant commands expose a typed Params struct
// with named fields — read/modify by field, then stringify. A command opts in by
// implementing Structured.

import (
	"fmt"
	"sort"
	"strings"
)

// Params is a typed view of a command's arguments: named fields you can inspect
// or edit, plus Args()/String() to render the invocation back to a command line.
type Params interface {
	fmt.Stringer
	Args() []string // full argv, including the command name
}

// Structured is implemented by commands that expose a typed Params struct.
type Structured interface {
	Params(p ParsedCommand) Params
}

// TypedParams returns the typed params for an invocation when its command
// implements Structured, else the generic ParsedCommand (which is itself a Params).
func (p ParsedCommand) TypedParams() Params {
	if s, ok := p.cmd.(Structured); ok {
		return s.Params(p)
	}
	return p
}

// Args renders the generic, normalized form: flags sorted for determinism;
// clustered short flags come out split.
func (p ParsedCommand) Args() []string {
	out := []string{p.Name}
	if p.Subcommand != "" {
		out = append(out, p.Subcommand)
	}
	names := make([]string, 0, len(p.Flags))
	for k := range p.Flags {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, v := range p.Flags[k] {
			switch {
			case v == "":
				out = append(out, k)
			case p.attached[k]:
				out = append(out, k+v)
			default:
				out = append(out, k, v)
			}
		}
	}
	return append(out, p.Operands...)
}

func (p ParsedCommand) String() string { return JoinArgs(p.Args()) }

// JoinArgs renders an argv as a shell-ish command line, quoting where needed.
func JoinArgs(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		parts[i] = quoteArg(a)
	}
	return strings.Join(parts, " ")
}

func quoteArg(a string) string {
	if a == "" {
		return "''"
	}
	if strings.ContainsAny(a, " \t\n\"'\\$&|;<>()*?[") {
		return "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return a
}

// CurlParams -----------------------------------------------------------------

// CurlParams is the tagged model of a curl invocation; see bind.go for the tag
// vocabulary. curlSpec is derived from it, plus the flags curl accepts that we
// don't model but must still parse as taking a value.
type CurlParams struct {
	Silent     bool     `flag:"-s,--silent"`
	ShowError  bool     `flag:"-S,--show-error"`
	FailFast   bool     `flag:"-f,--fail"`
	Follow     bool     `flag:"-L,--location"`
	Head       bool     `flag:"-I,--head"`
	RemoteName bool     `flag:"-O,--remote-name"`
	Method     string   `flag:"-X,--request"`
	UserAgent  string   `flag:"-A,--user-agent"`
	Referer    string   `flag:"-e,--referer"`
	Headers    []string `flag:"-H,--header" secret:"true"` // may carry Authorization
	Cookies    []string `flag:"-b,--cookie" secret:"true"`
	Data       []string `flag:"-d,--data,--data-raw,--data-binary,--data-urlencode" secret:"true"`
	WriteOut   string   `flag:"-w,--write-out"`              // printed after the transfer; %{http_code} and %{url_effective} are supported
	URL        string   `operand:"url" resource:"url,fetch"` // declared before Output so the log reads fetch-then-write
	Output     string   `flag:"-o,--output" resource:"path,write,stdout"`
}

var curlSpec = specOf(CurlParams{}, true,
	"-u", "--user", "--connect-timeout", "--max-time", "--retry", "--retry-delay",
	"--retry-max-time", "--proto", "--proto-default", "--proto-redir")

func curlParamsFrom(p ParsedCommand) (c CurlParams) { bind(p, &c); return c }
func (c CurlParams) Args() []string                 { return render("curl", c, true) }
func (c CurlParams) String() string                 { return JoinArgs(c.Args()) }

// WgetParams ------------------------------------------------------------------

// WgetParams models wget, whose -O/-o are ~the opposite of curl's: -O is the
// output file and -o is a logfile.
type WgetParams struct {
	Quiet     bool     `flag:"-q,--quiet"`
	Continue  bool     `flag:"-c,--continue"`
	URL       string   `operand:"url" resource:"url,fetch"`
	Output    string   `flag:"-O,--output-document" resource:"path,write"`
	Logfile   string   `flag:"-o,--output-file" resource:"path,write"`
	UserAgent string   `flag:"-U,--user-agent"`
	Headers   []string `flag:"--header" secret:"true"`
}

var wgetSpec = specOf(WgetParams{}, true,
	"-a", "--append-output", "--referer", "-t", "--tries", "-T", "--timeout",
	"-w", "--wait", "--waitretry", "-P", "--directory-prefix", "--post-data", "--post-file")

func wgetParamsFrom(p ParsedCommand) (w WgetParams) { bind(p, &w); return w }
func (w WgetParams) Args() []string                 { return render("wget", w, true) }
func (w WgetParams) String() string                 { return JoinArgs(w.Args()) }

// OpensslParams --------------------------------------------------------------

// OpensslParams models openssl as three things installers use it for:
// offline digests (dgst), TLS clients (s_client), and encryption/decryption
// (enc, rsautl/pkeyutl, smime/cms). Key material and passphrases are secret
// fields; everything else flows through Rest so an invocation round-trips.
type OpensslParams struct {
	Subcommand string   `role:"subcommand"`
	Connect    string   `flag:"-connect" resource:"host,connect"`
	ServerName string   `flag:"-servername"`
	Decrypt    bool     `flag:"-d,-decrypt"`
	Encrypt    bool     `flag:"-e,-encrypt"`
	In         string   `flag:"-in"`    // input file (default stdin); described by Openssl.Resources
	Out        string   `flag:"-out"`   // output file (default stdout)
	InKey      string   `flag:"-inkey"` // private/public key file for rsautl/pkeyutl/smime
	KeyFile    string   `flag:"-kfile" resource:"path,read"`
	PassIn     string   `flag:"-pass,-passin" secret:"true"`
	PassOut    string   `flag:"-passout" secret:"true"`
	Key        string   `flag:"-K,-k" secret:"true"` // raw hex key / password
	IV         string   `flag:"-iv"`
	Rest       []string `role:"rest" secret:"-hmac,-macopt,-password"` // unmodelled flags; listed ones are secrets
	Operands   []string `operand:"all"`
}

// opensslValueFlags are the unmodelled openssl flags that take a value.
var opensslValueFlags = []string{
	"-host", "-port", "-url", "-CAfile", "-CApath", "-cert", "-key", "-cipher", "-ciphersuites",
	"-md", "-iter", "-S", "-hmac", "-macopt", "-keyform", "-inform", "-outform", "-passwd",
	"-subj", "-days", "-newkey", "-keyout", "-signkey", "-CA", "-CAkey", "-extfile", "-config",
	"-name", "-certfile", "-recip", "-signer", "-content", "-pkeyopt", "-peerkey", "-sigfile",
	"-rand", "-writerand", "-starttls", "-alpn", "-sess_out", "-sess_in", "-engine",
}

var (
	opensslSpec = specOf(OpensslParams{}, false, opensslValueFlags...)
	// dgst: -sign/-verify/-prverify take a key file, -signature a file; elsewhere -sign is a bool.
	opensslDgstSpec = specOf(OpensslParams{}, false, append(opensslValueFlags, "-sign", "-verify", "-prverify", "-signature", "-sigopt")...)
)

func opensslParamsFrom(p ParsedCommand) (o OpensslParams) { bind(p, &o); return o }
func (o OpensslParams) Args() []string                    { return render("openssl", o, false) }
func (o OpensslParams) String() string                    { return JoinArgs(o.Args()) }

// Cipher returns the symmetric cipher an enc invocation uses: the shorthand
// subcommand (`openssl aes-256-cbc`) or a cipher flag in Rest.
func (o OpensslParams) Cipher() string {
	if isCipherName(o.Subcommand) {
		return o.Subcommand
	}
	for _, r := range o.Rest {
		if strings.HasPrefix(r, "-") && isCipherName(r[1:]) {
			return r[1:]
		}
	}
	return ""
}

var cipherPrefixes = []string{"aes", "aria", "bf", "blowfish", "camellia", "cast", "chacha20", "des", "des3", "idea", "rc2", "rc4", "rc5", "seed", "sm4"}

func isCipherName(s string) bool {
	for _, pre := range cipherPrefixes {
		if s == pre || strings.HasPrefix(s, pre+"-") || strings.HasPrefix(s, pre+"1") || strings.HasPrefix(s, pre+"2") {
			return true
		}
	}
	return false
}

// SSHParams / ScpParams / RsyncParams ----------------------------------------

type SSHParams struct {
	Port        string   `flag:"-p"`
	Login       string   `flag:"-l"`
	Identity    string   `flag:"-i"`
	Config      string   `flag:"-F"`
	JumpHost    string   `flag:"-J" resource:"host,connect"`
	Options     []string `flag:"-o"`
	Destination string   `operand:"first" resource:"host,connect"` // [user@]host or ssh://…
	// Command is everything after the destination (the remote command line).
	Command []string `resource:"command,run"`
}

var sshSpec = stopAtOperand(specOf(SSHParams{}, true,
	"-b", "-c", "-D", "-E", "-e", "-I", "-L", "-m", "-O", "-Q", "-R", "-S", "-W", "-w", "-B"))

func sshParamsFrom(p ParsedCommand) (s SSHParams) {
	bind(p, &s)
	if len(p.Operands) > 1 {
		s.Command = append([]string(nil), p.Operands[1:]...)
	}
	return s
}
func (s SSHParams) Args() []string { return append(render("ssh", s, true), s.Command...) }
func (s SSHParams) String() string { return JoinArgs(s.Args()) }

type ScpParams struct {
	Port      string   `flag:"-P"`
	Identity  string   `flag:"-i"`
	Config    string   `flag:"-F"`
	Options   []string `flag:"-o"`
	Recursive bool     `flag:"-r"`
	Preserve  bool     `flag:"-p"`
	Quiet     bool     `flag:"-q"`
	Paths     []string `operand:"all"` // SRC… DEST, any of which may be remote
}

var scpSpec = specOf(ScpParams{}, true, "-c", "-l", "-S", "-J", "-b", "-D")

func scpParamsFrom(p ParsedCommand) (s ScpParams) { bind(p, &s); return s }
func (s ScpParams) Args() []string                { return render("scp", s, true) }
func (s ScpParams) String() string                { return JoinArgs(s.Args()) }

type RsyncParams struct {
	Archive  bool     `flag:"-a,--archive"`
	Verbose  bool     `flag:"-v,--verbose"`
	Compress bool     `flag:"-z,--compress"`
	Delete   bool     `flag:"--delete"`
	DryRun   bool     `flag:"-n,--dry-run"`
	Rsh      string   `flag:"-e,--rsh"`
	Exclude  []string `flag:"--exclude"`
	Include  []string `flag:"--include"`
	Paths    []string `operand:"all"` // SRC… DEST
}

var rsyncSpec = specOf(RsyncParams{}, true,
	"--rsync-path", "--port", "--timeout", "--bwlimit", "--files-from", "--filter", "-f",
	"--log-file", "--chmod", "--password-file", "--exclude-from", "--include-from", "-T", "--temp-dir")

func rsyncParamsFrom(p ParsedCommand) (r RsyncParams) { bind(p, &r); return r }
func (r RsyncParams) Args() []string                  { return render("rsync", r, true) }
func (r RsyncParams) String() string                  { return JoinArgs(r.Args()) }

// DockerParams --------------------------------------------------------------

// DockerParams models Docker-compatible CLIs (docker, podman, nerdctl). Name
// retains the spelling used by the invocation. Rest holds subcommand-specific
// flags that do not warrant dedicated fields, while Image and Arguments split
// the container image from the command run inside it.
type DockerParams struct {
	Name       string
	Config     string   `flag:"--config"`
	Context    string   `flag:"--context"`
	Debug      bool     `flag:"-D,--debug"`
	Hosts      []string `flag:"-H,--host"`
	LogLevel   string   `flag:"--log-level"`
	TLS        bool     `flag:"--tls"`
	TLSVerify  bool     `flag:"--tlsverify"`
	TLSCACert  string   `flag:"--tlscacert"`
	TLSCert    string   `flag:"--tlscert"`
	TLSKey     string   `flag:"--tlskey"`
	Subcommand string   `role:"subcommand"`
	Rest       []string `role:"rest" secret:"--password"`
	Image      string   `operand:"first"`
	Arguments  []string `operand:"rest"`
}

func dockerParamsFrom(p ParsedCommand) (d DockerParams) {
	bind(p, &d)
	d.Name = p.Name
	// -c and -l are global aliases but collide with run's --cpu-shares and
	// --label. Bind them as globals only when they occur before the subcommand.
	if value, ok := dockerGlobalShortValue(p, "-c"); ok {
		d.Context = value
		d.Rest = removeFlagPair(d.Rest, "-c", value)
	}
	if value, ok := dockerGlobalShortValue(p, "-l"); ok {
		d.LogLevel = value
		d.Rest = removeFlagPair(d.Rest, "-l", value)
	}
	return d
}

func dockerGlobalShortValue(p ParsedCommand, flag string) (string, bool) {
	for i := 1; i < len(p.raw); i++ {
		if p.raw[i] == p.Subcommand {
			break
		}
		if p.raw[i] == flag && i+1 < len(p.raw) {
			return p.raw[i+1], true
		}
	}
	return "", false
}

func removeFlagPair(rest []string, flag, value string) []string {
	out := make([]string, 0, len(rest))
	removed := false
	for i := 0; i < len(rest); i++ {
		if !removed && rest[i] == flag && i+1 < len(rest) && rest[i+1] == value {
			i++
			removed = true
			continue
		}
		out = append(out, rest[i])
	}
	return out
}

// Args renders global options before the subcommand, then retained subcommand
// flags, the image, and any command arguments.
func (d DockerParams) Args() []string {
	name := d.Name
	if name == "" {
		name = "docker"
	}
	out := []string{name}
	appendValue := func(flag, value string) {
		if value != "" {
			out = append(out, flag, value)
		}
	}
	appendValue("--config", d.Config)
	appendValue("--context", d.Context)
	if d.Debug {
		out = append(out, "--debug")
	}
	for _, host := range d.Hosts {
		out = append(out, "--host", host)
	}
	appendValue("--log-level", d.LogLevel)
	if d.TLS {
		out = append(out, "--tls")
	}
	if d.TLSVerify {
		out = append(out, "--tlsverify")
	}
	appendValue("--tlscacert", d.TLSCACert)
	appendValue("--tlscert", d.TLSCert)
	appendValue("--tlskey", d.TLSKey)
	if d.Subcommand != "" {
		out = append(out, d.Subcommand)
	}
	out = append(out, d.Rest...)
	if d.Image != "" {
		out = append(out, d.Image)
	}
	return append(out, d.Arguments...)
}

func (d DockerParams) String() string { return JoinArgs(d.Args()) }

// PerlParams -----------------------------------------------------------------

// PerlParams models the perl command line well enough to see what it loads and
// runs. With Code set, Operands are the code's arguments; otherwise the first
// operand is a script file.
type PerlParams struct {
	Warnings bool     `flag:"-w"`
	Modules  []string `flag:"-M,-m"` // -MLWP::Simple (attached) or -M LWP::Simple
	Includes []string `flag:"-I"`
	Code     []string `flag:"-e,-E"`
	Operands []string `operand:"all"`
}

var perlSpec = stopAtOperand(specOf(PerlParams{}, true, "-C", "-d", "-D", "-F", "-x"))

func perlParamsFrom(p ParsedCommand) (pp PerlParams) { bind(p, &pp); return pp }
func (pp PerlParams) Args() []string                 { return render("perl", pp, true) }
func (pp PerlParams) String() string                 { return JoinArgs(pp.Args()) }

// Script returns the script file perl would run, or "" when running -e code.
func (pp PerlParams) Script() string {
	if len(pp.Code) == 0 && len(pp.Operands) > 0 {
		return pp.Operands[0]
	}
	return ""
}

// Base64Params ---------------------------------------------------------------

type Base64Params struct {
	Decode        bool   `flag:"-d,--decode,-D"`
	IgnoreGarbage bool   `flag:"-i,--ignore-garbage"`
	Wrap          string `flag:"-w,--wrap"`
	File          string `operand:"first" resource:"path,read,stdin"` // input file; "" or "-" is stdin
}

var base64Spec = specOf(Base64Params{}, true)

func base64ParamsFrom(p ParsedCommand) (b Base64Params) { bind(p, &b); return b }
func (b Base64Params) Args() []string                   { return render("base64", b, true) }
func (b Base64Params) String() string                   { return JoinArgs(b.Args()) }

// PythonParams ---------------------------------------------------------------

// PythonParams models the python command line well enough to see what it runs:
// inline -c code, a -m module, or a script file. With Code or Module set the
// operands are that program's arguments; otherwise the first operand is the
// script. Name keeps the spelling the script used (python, python2, python3)
// so rendering round-trips.
type PythonParams struct {
	Name       string
	Unbuffered bool     `flag:"-u"`
	Isolated   bool     `flag:"-I"`
	NoSite     bool     `flag:"-S"`
	Optimize   bool     `flag:"-O"`
	Module     string   `flag:"-m"`
	Code       []string `flag:"-c"`
	Operands   []string `operand:"all"`
}

var pythonSpec = stopAtOperand(specOf(PythonParams{}, true, "-W", "-X", "-Q", "--check-hash-based-pycs"))

func pythonParamsFrom(p ParsedCommand) (pp PythonParams) {
	bind(p, &pp)
	pp.Name = p.Name
	if pp.Name == "" {
		pp.Name = "python3"
	}
	return pp
}

func (pp PythonParams) Args() []string { return render(pp.Name, pp, true) }
func (pp PythonParams) String() string { return JoinArgs(pp.Args()) }

// Script returns the script file python would run, or "" when running -c code
// or a -m module.
func (pp PythonParams) Script() string {
	if len(pp.Code) == 0 && pp.Module == "" && len(pp.Operands) > 0 {
		return pp.Operands[0]
	}
	return ""
}

// FindParams ------------------------------------------------------------------

// FindParams splits a find invocation into its starting Paths and its
// Expression (the predicate mini-language), since find is order-sensitive. The
// security-relevant `-exec` command is exposed via ExecArgv.
type FindParams struct {
	Paths      []string // starting points, e.g. ["." "/tmp"]
	Expression []string // predicates, e.g. -name *.log -type f -exec rm {} ;
}

func findParamsFrom(args []string) FindParams {
	var fp FindParams
	i := 0
	if len(args) > 0 {
		i = 1 // skip "find"
	}
	for i < len(args) { // leading global options: -H -L -P
		if a := args[i]; a == "-H" || a == "-L" || a == "-P" {
			i++
			continue
		}
		break
	}
	for i < len(args) && !strings.HasPrefix(args[i], "-") { // paths
		fp.Paths = append(fp.Paths, args[i])
		i++
	}
	fp.Expression = append([]string{}, args[i:]...) // the expression
	return fp
}

// ExecArgv returns the command run by -exec/-execdir/-ok/-okdir (up to the
// ;/+ terminator — mvdan/sh has already unescaped `\;` to `;`), or nil. This is
// what the sandbox enforces on.
func (p FindParams) ExecArgv() []string {
	for i, tok := range p.Expression {
		switch tok {
		case "-exec", "-execdir", "-ok", "-okdir":
			var inner []string
			for _, a := range p.Expression[i+1:] {
				if a == ";" || a == "+" {
					break
				}
				inner = append(inner, a)
			}
			return inner
		}
	}
	return nil
}

func (p FindParams) Args() []string {
	a := append([]string{"find"}, p.Paths...)
	return append(a, p.Expression...)
}

func (p FindParams) String() string { return JoinArgs(p.Args()) }

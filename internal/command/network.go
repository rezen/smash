package command

import (
	"net/http"
	"regexp"
	"strings"
)

// networkCommands are the families capable of egress; each implements Networked.
var networkCommands = append([]Command{
	Curl{}, Wget{}, Openssl{}, SSH{}, Scp{}, Rsync{}, DockerCommand{}, Netcat{}, Git{}, Perl{}, Python{}, Gpg{},
}, netTools...)

// Request is the parsed intent of a downloader (curl/wget) invocation — what a
// sandbox needs to serve the fetch itself instead of spawning a host binary.
type Request struct {
	URL        string
	Method     string // "" means GET
	Headers    http.Header
	Output     string // -o FILE (curl) / -O FILE (wget); "" or "-" means stdout
	RemoteName bool   // curl -O: name the output after the URL's last path segment
	Follow     bool   // follow redirects (curl -L; wget always)
	FailOnHTTP bool   // fail on HTTP status >= 400 (curl -f)
	Head       bool   // HEAD request, print headers (curl -I)
	WriteOut   string // curl -w: format printed to stdout after the transfer
	Body       []RequestBodyPart
}

// RequestBodyPart is one curl data flag. File names are resolved and confined
// by the sandbox package, not read by the pure command model.
type RequestBodyPart struct {
	Value         string
	Prefix        string
	File          bool
	StripNewlines bool
	URLEncode     bool
}

// Downloader is implemented by fetchers whose invocation can be served
// in-process from a Request.
type Downloader interface {
	Request(p ParsedCommand) Request
}

// urlOperand finds the URL a fetcher targets: the first operand with a scheme,
// else the first operand (a bare host). Shared by curl and wget.
func urlOperand(p ParsedCommand) (string, bool) {
	for _, o := range p.Operands {
		if strings.Contains(o, "://") {
			return o, true
		}
	}
	if len(p.Operands) > 0 {
		return p.Operands[0], true
	}
	return "", false
}

// addHeaderLine parses a `Name: value` header line into h.
func addHeaderLine(h http.Header, line string) {
	if k, v, ok := strings.Cut(line, ":"); ok {
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
}

// Curl ----------------------------------------------------------------------

type Curl struct{}

func (Curl) Names() []string                       { return []string{"curl"} }
func (Curl) Parse(a []string) ParsedCommand        { return curlSpec.Parse(a) }
func (Curl) Egress(p ParsedCommand) (string, bool) { return urlOperand(p) }
func (Curl) Params(p ParsedCommand) Params         { return curlParamsFrom(p) }
func (Curl) Request(p ParsedCommand) Request {
	r := curlParamsFrom(p).Request()
	r.Body = curlBodyParts(p)
	if len(r.Body) > 0 && r.Method == "" {
		r.Method = "POST"
	}
	return r
}

// Request converts the typed params to a fetch intent.
func (c CurlParams) Request() Request {
	r := Request{
		URL:        c.URL,
		Method:     strings.ToUpper(c.Method),
		Headers:    http.Header{},
		Output:     c.Output,
		RemoteName: c.RemoteName,
		Follow:     c.Follow,
		FailOnHTTP: c.FailFast,
		Head:       c.Head,
		WriteOut:   c.WriteOut,
	}
	for _, h := range c.Headers {
		addHeaderLine(r.Headers, h)
	}
	if c.UserAgent != "" {
		r.Headers.Set("User-Agent", c.UserAgent)
	}
	if c.Referer != "" {
		r.Headers.Set("Referer", c.Referer)
	}
	for _, ck := range c.Cookies {
		r.Headers.Add("Cookie", ck)
	}
	for _, value := range c.Data {
		r.Body = append(r.Body, RequestBodyPart{Value: value, StripNewlines: true})
	}
	if len(c.Data) > 0 && r.Method == "" {
		r.Method = "POST"
	}
	return r
}

func curlBodyParts(p ParsedCommand) []RequestBodyPart {
	var parts []RequestBodyPart
	add := func(values []string, raw, binary, encoded bool) {
		for _, value := range values {
			part := RequestBodyPart{Value: value, StripNewlines: !binary, URLEncode: encoded}
			if !raw && strings.HasPrefix(value, "@") {
				part.File = true
				part.Value = strings.TrimPrefix(value, "@")
			}
			parts = append(parts, part)
		}
	}
	add(p.Values("-d", "--data"), false, false, false)
	add(p.Values("--data-raw"), true, false, false)
	add(p.Values("--data-binary"), false, true, false)
	for _, value := range p.Values("--data-urlencode") {
		part := RequestBodyPart{URLEncode: true}
		switch {
		case strings.HasPrefix(value, "@"):
			part.File, part.Value = true, strings.TrimPrefix(value, "@")
		case strings.Contains(value, "="):
			name, content, _ := strings.Cut(value, "=")
			part.Prefix, part.Value = name+"=", content
		case strings.Contains(value, "@"):
			name, file, _ := strings.Cut(value, "@")
			part.Prefix, part.Value, part.File = name+"=", file, true
		default:
			part.Value = value
		}
		parts = append(parts, part)
	}
	return parts
}

// Wget ----------------------------------------------------------------------

type Wget struct{}

func (Wget) Names() []string                       { return []string{"wget", "wget2"} }
func (Wget) Parse(a []string) ParsedCommand        { return wgetSpec.Parse(a) }
func (Wget) Egress(p ParsedCommand) (string, bool) { return urlOperand(p) }
func (Wget) Params(p ParsedCommand) Params         { return wgetParamsFrom(p) }
func (Wget) Request(p ParsedCommand) Request       { return wgetParamsFrom(p).Request() }

// Request converts the typed params to a fetch intent. wget always follows
// redirects.
func (w WgetParams) Request() Request {
	r := Request{URL: w.URL, Headers: http.Header{}, Output: w.Output, Follow: true}
	for _, h := range w.Headers {
		addHeaderLine(r.Headers, h)
	}
	if w.UserAgent != "" {
		r.Headers.Set("User-Agent", w.UserAgent)
	}
	return r
}

// Openssl -------------------------------------------------------------------

type Openssl struct{}

func (Openssl) Names() []string { return []string{"openssl"} }
func (Openssl) Parse(a []string) ParsedCommand {
	if opensslSubcommand(a) == "dgst" {
		return opensslDgstSpec.Parse(a)
	}
	return opensslSpec.Parse(a)
}

// opensslSubcommand peeks at the subcommand so Parse can pick the right Spec.
func opensslSubcommand(a []string) string {
	for _, x := range a[1:] {
		if !strings.HasPrefix(x, "-") {
			return x
		}
	}
	return ""
}
func (Openssl) Params(p ParsedCommand) Params { return opensslParamsFrom(p) }

// Egress: s_client/s_server/s_time always reach out; -connect/-host/-url do on
// any subcommand.
func (Openssl) Egress(p ParsedCommand) (string, bool) {
	networked := false
	switch p.Subcommand {
	case "s_client", "s_server", "s_time":
		networked = true
	case "ocsp":
		if v, ok := p.FlagValue("-url"); ok {
			return v, true
		}
	}
	if v, ok := p.FirstValue("-connect", "-host"); ok {
		return v, true
	}
	if networked {
		return p.Subcommand, true
	}
	return "", false
}

// SSH / Scp / Rsync ---------------------------------------------------------

// SSH is the interactive/remote-command client. Its destination operand
// (user@host, host, ssh://…) is the egress target; -J jump hosts count too.
type SSH struct{}

func (SSH) Names() []string                { return []string{"ssh"} }
func (SSH) Parse(a []string) ParsedCommand { return sshSpec.Parse(a) }
func (SSH) Params(p ParsedCommand) Params  { return sshParamsFrom(p) }
func (SSH) Egress(p ParsedCommand) (string, bool) {
	sp := sshParamsFrom(p)
	if sp.Destination != "" {
		return sp.Destination, true
	}
	if sp.JumpHost != "" {
		return sp.JumpHost, true
	}
	return "", false
}

// Scp covers scp and sftp, whose flags differ from ssh's (-P is the port, -p
// preserves times). A remote operand is host:path or user@host:path — a colon
// before the first slash — or an scp:// / sftp:// URL.
type Scp struct{}

func (Scp) Names() []string                { return []string{"scp", "sftp"} }
func (Scp) Parse(a []string) ParsedCommand { return scpSpec.Parse(a) }
func (Scp) Params(p ParsedCommand) Params  { return scpParamsFrom(p) }
func (Scp) Egress(p ParsedCommand) (string, bool) {
	paths := scpParamsFrom(p).Paths
	if p.Name == "sftp" && len(paths) == 1 {
		return paths[0], true // `sftp [user@]host`: the lone operand is the host
	}
	return remoteOperand(paths)
}

// Rsync egresses whenever a SRC or DEST operand is remote: rsync://host/…,
// host::module (daemon), or [user@]host:path.
type Rsync struct{}

func (Rsync) Names() []string                { return []string{"rsync"} }
func (Rsync) Parse(a []string) ParsedCommand { return rsyncSpec.Parse(a) }
func (Rsync) Params(p ParsedCommand) Params  { return rsyncParamsFrom(p) }
func (Rsync) Egress(p ParsedCommand) (string, bool) {
	return remoteOperand(rsyncParamsFrom(p).Paths)
}

// remoteOperand returns the first path operand that names a remote endpoint:
// a URL, or a colon before the first slash (host:path, user@host:path,
// host::module). Local paths never match — a colon inside a directory name
// needs a leading ./ or /, which puts the slash first.
func remoteOperand(paths []string) (string, bool) {
	for _, o := range paths {
		if strings.Contains(o, "://") {
			return o, true
		}
		colon, slash := strings.IndexByte(o, ':'), strings.IndexByte(o, '/')
		if colon > 0 && (slash < 0 || colon < slash) {
			return o, true
		}
	}
	return "", false
}

// Netcat --------------------------------------------------------------------

var netcatSpec = Spec{ValueFlags: NewSet("-p", "-s", "-w", "-X", "-x")}

type Netcat struct{}

func (Netcat) Names() []string                { return []string{"nc", "ncat", "netcat", "socat"} }
func (Netcat) Parse(a []string) ParsedCommand { return netcatSpec.Parse(a) }
func (Netcat) Egress(p ParsedCommand) (string, bool) {
	if len(p.Operands) > 0 {
		return strings.Join(p.Operands, ":"), true
	}
	return "", false
}

// Git -----------------------------------------------------------------------

var (
	gitSpec = Spec{Subcommand: true, ValueFlags: NewSet(
		"-C", "-c", "--git-dir", "--work-tree", "--exec-path", "--namespace",
		"--upload-pack", "--depth", "-o", "-b", "--branch")}
	gitRemoteSubcommands = NewSet("clone", "fetch", "pull", "push", "ls-remote", "remote", "submodule")
	// gitNamedRemote subcommands take the remote as their first operand and
	// default to "origin" when it is omitted.
	gitNamedRemote = NewSet("fetch", "pull", "push", "ls-remote")
)

type Git struct{}

func (Git) Names() []string                { return []string{"git"} }
func (Git) Parse(a []string) ParsedCommand { return gitSpec.Parse(a) }

// Egress returns the remote a network subcommand reaches: a URL when one is
// given, otherwise the remote NAME (`git fetch origin tag v1`, or "origin" when
// none is named). A name is only meaningful in a repository — the sandbox
// resolves it through .git/config — so a caller without one must treat it as
// unknown. `--all`/`--multiple` and `remote update` name no single remote and
// report the subcommand itself.
func (Git) Egress(p ParsedCommand) (string, bool) {
	for _, setting := range p.Values("-c") {
		if dangerousGitConfig(setting) {
			return "unsafe git config", true
		}
	}
	if p.Subcommand == "submodule" {
		return "submodule", true // may read URLs and helpers from repository state
	}
	if !gitRemoteSubcommands[p.Subcommand] {
		return "", false
	}
	for _, o := range p.Operands {
		if strings.Contains(o, "://") || strings.Contains(o, "@") {
			return o, true
		}
	}
	if gitNamedRemote[p.Subcommand] && !p.HasFlag("--all", "--multiple") {
		if len(p.Operands) > 0 {
			return p.Operands[0], true
		}
		return "origin", true
	}
	return p.Subcommand, true
}

// dangerousGitConfig identifies command-line settings that can rewrite a
// checked remote, choose an arbitrary transport/helper, or execute a command.
// Real git remains an explicit unsafe capability; this closes the common
// textual-host bypasses for callers that nevertheless grant it.
func dangerousGitConfig(setting string) bool {
	key, _, _ := strings.Cut(strings.ToLower(setting), "=")
	return strings.HasPrefix(key, "alias.") ||
		strings.HasPrefix(key, "url.") && (strings.HasSuffix(key, ".insteadof") || strings.HasSuffix(key, ".pushinsteadof")) ||
		strings.HasPrefix(key, "remote.") && (strings.HasSuffix(key, ".url") || strings.HasSuffix(key, ".pushurl") || strings.HasSuffix(key, ".vcs")) ||
		key == "core.sshcommand" || key == "core.gitproxy" ||
		key == "http.proxy" || key == "https.proxy" ||
		key == "credential.helper" || strings.HasPrefix(key, "protocol.")
}

// Perl ----------------------------------------------------------------------

// Perl is an escape hatch in its own right — `perl -e` runs arbitrary code and
// can open sockets — so it is Networked, but its egress detection is a
// HEURISTIC: it looks for network modules loaded with -M/-m or named in inline
// -e/-E code, and for URLs in that code. A script file (`perl fetch.pl`) is
// opaque; the allow-list, not this indicator, is the real gate for perl.
type Perl struct{}

var perlNetModules = []string{
	"LWP", "HTTP::", "Net::", "IO::Socket", "Socket", "WWW::", "Mojo::UserAgent", "URI::Fetch",
}

var urlInCode = regexp.MustCompile(`https?://[^\s'"\)]+`)

func (Perl) Names() []string                { return []string{"perl"} }
func (Perl) Parse(a []string) ParsedCommand { return perlSpec.Parse(a) }
func (Perl) Params(p ParsedCommand) Params  { return perlParamsFrom(p) }
func (Perl) Egress(p ParsedCommand) (string, bool) {
	pp := perlParamsFrom(p)
	for _, m := range pp.Modules {
		if isPerlNetModule(m) {
			return m, true
		}
	}
	for _, code := range pp.Code {
		if u := urlInCode.FindString(code); u != "" {
			return u, true
		}
		for _, m := range perlNetModules {
			if strings.Contains(code, m) {
				return m, true
			}
		}
		if strings.Contains(code, "socket(") {
			return "socket", true
		}
	}
	return "", false
}

func isPerlNetModule(m string) bool {
	m, _, _ = strings.Cut(m, "=") // -MLWP::Simple=getstore
	for _, n := range perlNetModules {
		if strings.HasPrefix(m, n) {
			return true
		}
	}
	return false
}

// Python ---------------------------------------------------------------------

// Python is the other escape hatch: `python -c` runs arbitrary code, `python
// -m` runs any installed module, and both have well-known one-liners — the
// throwaway servers (`python3 -m http.server 8000`) and the
// socket/subprocess/pty reverse shells — so it is Networked. Like Perl, the
// detection is a HEURISTIC over the module name and the inline code; a script
// file (`python fetch.py`) is opaque, and there the allow-list, not this
// indicator, is the gate.
type Python struct{}

// pythonNetModules are the modules that reach the network, matched on dotted
// name boundaries so "http" covers http.client and http.server but not httpx's
// neighbours. Both Python 2 and Python 3 spellings are listed: an installer's
// one-liner picks whichever interpreter it found. Modules that only *look*
// networked are left out — `ssl` inspects a version, `venv` and `ensurepip`
// install bundled wheels — since installers use them offline and a false
// denial there costs more than the narrow gap (`venv --upgrade-deps`).
var pythonNetModules = []string{
	"socket", "socketserver", "SocketServer",
	"http", "httplib", "httplib2", "SimpleHTTPServer", "CGIHTTPServer", "BaseHTTPServer",
	"urllib", "urllib2", "urllib3", "xmlrpc", "xmlrpclib", "webbrowser", "wsgiref",
	"ftplib", "telnetlib", "smtplib", "smtpd", "poplib", "imaplib", "nntplib",
	"requests", "httpx", "aiohttp", "websocket", "websockets", "paramiko", "fabric",
	"boto3", "botocore", "scapy", "twisted", "tornado", "pycurl", "mechanize",
	"pip", "uvicorn", "gunicorn", "waitress",
	"flask", "django", "bottle", "pydoc",
}

// connectTuple matches the address a socket one-liner dials —
// `s.connect(("10.0.0.1",1234))` — so the audit log and the egress guard see
// the endpoint itself rather than just "socket".
var connectTuple = regexp.MustCompile(`connect(?:_ex)?\(\s*\(\s*["']([^"']+)["']\s*,\s*(\d+)`)

// pythonImport matches the modules an inline program pulls in, by either
// spelling: `import socket,subprocess,os` and `from http.server import …`.
var pythonImport = regexp.MustCompile(`\b(?:import|from)\s+([\w.,\s]+)`)

func (Python) Names() []string                { return []string{"python", "python2", "python3"} }
func (Python) Parse(a []string) ParsedCommand { return pythonSpec.Parse(a) }
func (Python) Params(p ParsedCommand) Params  { return pythonParamsFrom(p) }
func (Python) Egress(p ParsedCommand) (string, bool) {
	pp := pythonParamsFrom(p)
	if isPythonNetModule(pp.Module) {
		return pythonModuleTarget(pp), true
	}
	for _, code := range pp.Code {
		// The dialled endpoint first: it is the most specific target, and a
		// reverse shell that also mentions an allow-listed URL must not pass
		// the egress guard on the strength of that URL.
		if m := connectTuple.FindStringSubmatch(code); m != nil {
			return m[1] + ":" + m[2], true
		}
		if u := urlInCode.FindString(code); u != "" {
			return u, true
		}
		for _, imported := range pythonImports(code) {
			if isPythonNetModule(imported) {
				return imported, true
			}
		}
		if strings.Contains(code, "socket.socket(") {
			return "socket", true
		}
	}
	return "", false
}

// pythonModuleTarget names what a networked -m module reaches: the module and
// its first operand — the port for `-m http.server 8000`, the subcommand for
// `-m pip install …` — so the target says which one-liner ran.
func pythonModuleTarget(pp PythonParams) string {
	if len(pp.Operands) > 0 {
		return pp.Module + " " + pp.Operands[0]
	}
	return pp.Module
}

// pythonImports lists the module names an inline program imports.
func pythonImports(code string) []string {
	var out []string
	for _, m := range pythonImport.FindAllStringSubmatch(code, -1) {
		// `from socket import socket` puts the keyword inside the match; it is
		// not a module name, so a stray "import" token simply never matches.
		out = append(out, strings.FieldsFunc(m[1], func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n'
		})...)
	}
	return out
}

// isPythonNetModule matches on dotted-name boundaries: "http" covers
// http.client, "socket" does not cover socketpair.
func isPythonNetModule(m string) bool {
	m = strings.TrimSpace(m)
	for _, n := range pythonNetModules {
		if m == n || strings.HasPrefix(m, n+".") {
			return true
		}
	}
	return false
}

package command

// Describer implementations: the commands whose resources need a little
// logic rather than a field tag. Kept together because they serve one
// concern (audit logging) and the rules are easiest to compare side by side.

import "strings"

// Tool: operands as OperandKind (or plain operands); stdin when a filter is
// given nothing to read.
func (t Tool) Resources(p ParsedCommand) []Resource {
	kind, action := t.OperandKind, ""
	if kind == "" {
		kind = "operand"
	} else if kind == "path" {
		action = "read"
	}
	return operandResources(p, kind, action, t.Stdin)
}

// Grep: patterns from -e/-f or the first operand; files after, or stdin.
func (Grep) Resources(p ParsedCommand) []Resource {
	files := p.Operands
	if !p.HasFlag("-e", "--regexp", "-f", "--file") && len(files) > 0 {
		files = files[1:] // first operand is the pattern
	}
	rs := []Resource{}
	for _, f := range p.Values("-f", "--file") {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: f})
	}
	return append(rs, filesOrStdin(files)...)
}

// Sed: script from -e/-f or the first operand; files after, or stdin. -i
// edits those files in place.
func (Sed) Resources(p ParsedCommand) []Resource {
	files := p.Operands
	if !p.HasFlag("-e", "--expression", "-f", "--file") && len(files) > 0 {
		files = files[1:]
	}
	rs := []Resource{}
	for _, f := range p.Values("-f", "--file") {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: f})
	}
	if inPlace := p.HasFlag("-i", "--in-place"); inPlace && len(files) > 0 {
		for _, f := range files {
			rs = append(rs, Resource{Kind: "path", Action: "modify", Value: f})
		}
		return rs
	}
	return append(rs, filesOrStdin(files)...)
}

// Awk: program from -f or the first operand; files after, or stdin.
func (Awk) Resources(p ParsedCommand) []Resource {
	files := p.Operands
	if !p.HasFlag("-f") && len(files) > 0 {
		files = files[1:]
	}
	rs := []Resource{}
	for _, f := range p.Values("-f") {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: f})
	}
	return append(rs, filesOrStdin(files)...)
}

// Tar: the archive (-f, else stdin/stdout by direction), -C directory, and
// the member paths.
func (Tar) Resources(p ParsedCommand) []Resource {
	create := p.HasFlag("-c", "--create", "-r", "-u")
	action := "read"
	if create {
		action = "write"
	}
	var rs []Resource
	if f, ok := p.FirstValue("-f", "--file"); ok && f != "-" {
		rs = append(rs, Resource{Kind: "archive", Action: action, Value: f})
	} else if create {
		rs = append(rs, streamResource("stdout", "write"))
	} else {
		rs = append(rs, streamResource("stdin", "read"))
	}
	if dir, ok := p.FirstValue("-C", "--directory"); ok {
		rs = append(rs, Resource{Kind: "path", Action: "chdir", Value: dir})
	}
	memberAction := "write" // extracting writes members
	if create || p.HasFlag("-t", "--list") {
		memberAction = "read"
	}
	for _, o := range p.Operands {
		rs = append(rs, Resource{Kind: "path", Action: memberAction, Value: o})
	}
	return rs
}

// Find: the starting paths (read) and any -exec command (run).
func (Find) Resources(p ParsedCommand) []Resource {
	fp := findParamsFrom(p.raw)
	var rs []Resource
	for _, path := range fp.Paths {
		rs = append(rs, Resource{Kind: "path", Action: "read", Value: path})
	}
	if ex := fp.ExecArgv(); len(ex) > 0 {
		rs = append(rs, Resource{Kind: "command", Action: "run", Value: JoinArgs(ex)})
	}
	return rs
}

// Shell: `sh -c CODE` runs a script string, `sh FILE` runs a file, bare `sh`
// reads the script from stdin.
func (Shell) Resources(p ParsedCommand) []Resource {
	if script, _, ok := extractDashC(p.raw); ok {
		return []Resource{{Kind: "script", Action: "run", Value: script}}
	}
	if len(p.Operands) > 0 {
		return []Resource{{Kind: "path", Action: "run", Value: p.Operands[0]}}
	}
	return []Resource{streamResource("stdin", "run")}
}

// Perl: modules loaded, then -e code, a script file, or stdin.
func (Perl) Resources(p ParsedCommand) []Resource {
	pp := perlParamsFrom(p)
	var rs []Resource
	for _, m := range pp.Modules {
		rs = append(rs, Resource{Kind: "module", Action: "load", Value: m})
	}
	switch {
	case len(pp.Code) > 0:
		rs = append(rs, Resource{Kind: "code", Action: "run", Value: strings.Join(pp.Code, "; ")})
	case pp.Script() != "":
		rs = append(rs, Resource{Kind: "path", Action: "run", Value: pp.Script()})
	default:
		rs = append(rs, streamResource("stdin", "run"))
	}
	return rs
}

// Python: the module it runs (`-m http.server`), then -c code, a script file,
// or stdin. A one-liner that dials out also names the endpoint it reaches, so
// the log line carries the address and not just the code.
func (py Python) Resources(p ParsedCommand) []Resource {
	pp := pythonParamsFrom(p)
	var rs []Resource
	if pp.Module != "" {
		rs = append(rs, Resource{Kind: "module", Action: "run", Value: pp.Module})
	}
	switch {
	case len(pp.Code) > 0:
		rs = append(rs, Resource{Kind: "code", Action: "run", Value: strings.Join(pp.Code, "; ")})
		if target, ok := py.Egress(p); ok {
			if isPythonNetModule(target) { // a module name, not an address
				rs = append(rs, Resource{Kind: "module", Action: "load", Value: target})
			} else {
				rs = append(rs, Resource{Kind: kindOf(target), Action: "connect", Value: target})
			}
		}
	case pp.Module != "":
	case pp.Script() != "":
		rs = append(rs, Resource{Kind: "path", Action: "run", Value: pp.Script()})
	default:
		rs = append(rs, streamResource("stdin", "run"))
	}
	return rs
}

// Scp / Rsync: each operand is a remote endpoint or a local path.
func (Scp) Resources(p ParsedCommand) []Resource {
	return pathResources(scpParamsFrom(p).Paths, "copy")
}

func (Rsync) Resources(p ParsedCommand) []Resource {
	return pathResources(rsyncParamsFrom(p).Paths, "sync")
}

// InstallCommand: sources are read, the destination (or -t dir / -d dirs) written.
func (InstallCommand) Resources(p ParsedCommand) []Resource {
	i := installParamsFrom(p)
	targets := NewSet(i.Targets()...)
	var rs []Resource
	if i.Mode != "" {
		rs = append(rs, Resource{Kind: "mode", Action: "apply", Value: i.Mode})
	}
	if i.Owner != "" {
		rs = append(rs, Resource{Kind: "owner", Action: "apply", Value: i.Owner})
	}
	if i.Group != "" {
		rs = append(rs, Resource{Kind: "group", Action: "apply", Value: i.Group})
	}
	for _, o := range i.Operands {
		if !targets[o] {
			rs = append(rs, Resource{Kind: "path", Action: "read", Value: o})
		}
	}
	for _, t := range i.Targets() {
		rs = append(rs, Resource{Kind: "path", Action: "write", Value: t})
	}
	return rs
}

// Gpg: a keyserver operation, else the files it verifies/decrypts (or stdin).
func (Gpg) Resources(p ParsedCommand) []Resource {
	if ks, ok := p.FlagValue("--keyserver"); ok && ks != "" {
		return []Resource{{Kind: "keyserver", Action: "connect", Value: ks}}
	}
	for _, op := range gpgNetOps {
		if p.HasFlag(op) {
			return []Resource{{Kind: "keyserver", Action: strings.TrimPrefix(op, "--"), Value: strings.Join(p.Operands, " ")}}
		}
	}
	return filesOrStdin(p.Operands)
}

// Git: the remote on network subcommands, else the repository paths.
func (g Git) Resources(p ParsedCommand) []Resource {
	if target, ok := g.Egress(p); ok {
		return []Resource{{Kind: "repo", Action: p.Subcommand, Value: target}}
	}
	return operandResources(p, "path", "", false)
}

// Netcat: the host:port it dials (or listens on with -l).
func (n Netcat) Resources(p ParsedCommand) []Resource {
	action := "connect"
	if p.HasFlag("-l", "--listen") {
		action = "listen"
	}
	if target, ok := n.Egress(p); ok {
		return []Resource{{Kind: "socket", Action: action, Value: target}}
	}
	return nil
}

// Openssl: TLS clients connect; everything else transforms an input (file or
// stdin) into an output (file or stdout) with an action that says what the
// transform is — encrypt, decrypt, sign, verify, digest — plus the key files
// it reads. Passphrases and raw keys are secret fields, never resources.
func (Openssl) Resources(p ParsedCommand) []Resource {
	o := opensslParamsFrom(p)
	switch o.Subcommand {
	case "s_client", "s_server", "s_time":
		if o.Connect != "" {
			return []Resource{{Kind: "host", Action: "connect", Value: o.Connect}}
		}
		return nil
	}
	switch o.Subcommand {
	case "rand": // the operand is a byte count, not a file
		rs := []Resource{{Kind: "random", Action: "generate", Value: strings.Join(o.Operands, " ")}}
		if o.Out != "" {
			return append(rs, Resource{Kind: "path", Action: "write", Value: o.Out})
		}
		return append(rs, streamResource("stdout", "write"))
	case "passwd": // the operand IS a password: never log it
		return []Resource{{Kind: "password", Action: "hash"}, streamResource("stdout", "write")}
	}
	action, keyFiles, writes := opensslAction(p, o)
	var rs []Resource
	in := o.In
	if in == "" && len(o.Operands) > 0 { // dgst FILE…, x509 etc. take operands too
		for _, f := range o.Operands {
			rs = append(rs, Resource{Kind: "path", Action: action, Value: f})
		}
	} else if in != "" {
		rs = append(rs, Resource{Kind: "path", Action: action, Value: in})
	} else {
		rs = append(rs, streamResource("stdin", action))
	}
	for _, k := range keyFiles {
		rs = append(rs, Resource{Kind: "key", Action: "read", Value: k})
	}
	if o.KeyFile != "" {
		rs = append(rs, Resource{Kind: "key", Action: "read", Value: o.KeyFile})
	}
	if o.Out != "" {
		rs = append(rs, Resource{Kind: "path", Action: "write", Value: o.Out})
	} else if writes {
		rs = append(rs, streamResource("stdout", "write"))
	}
	return rs
}

// opensslAction names the transform, the key files involved, and whether the
// subcommand produces output worth logging when it goes to stdout.
func opensslAction(p ParsedCommand, o OpensslParams) (action string, keyFiles []string, writes bool) {
	sub := o.Subcommand
	if isCipherName(sub) {
		sub = "enc"
	}
	switch sub {
	case "enc", "aes", "des", "bf":
		if o.Decrypt {
			return "decrypt", nil, true
		}
		return "encrypt", nil, true
	case "dgst", "sha256", "sha1", "sha512", "md5", "sha3-256":
		if k, ok := p.FlagValue("-sign"); ok && k != "" {
			return "sign", []string{k}, true
		}
		if k, ok := p.FirstValue("-verify", "-prverify"); ok {
			return "verify", []string{k}, false
		}
		return "digest", nil, false
	case "rsautl", "pkeyutl", "smime", "cms":
		keys := []string{}
		if o.InKey != "" {
			keys = append(keys, o.InKey)
		}
		switch {
		case p.HasFlag("-decrypt"):
			return "decrypt", keys, true
		case p.HasFlag("-encrypt"):
			return "encrypt", keys, true
		case p.HasFlag("-sign"):
			return "sign", keys, true
		case p.HasFlag("-verify"):
			return "verify", keys, true
		}
		return "read", keys, true
	case "genrsa", "genpkey", "ecparam", "req", "x509", "pkcs12", "pkcs8", "rsa", "pkey", "ec":
		return "read", nil, true
	}
	return "read", nil, false
}

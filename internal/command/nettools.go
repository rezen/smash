package command

// The long tail of network-capable tools. Most share one shape — "the first
// operand is the host or URL" — with a few well-known twists (dig's @server,
// VCS/container tools that only egress on some subcommands, DB clients that
// only egress when given a host). NetTool captures those rules as data so each
// entry is one line, and every one is Networked for the egress guard.

import "strings"

// NetTool is a data-driven Networked command. Egress is decided in order:
//
//  1. Subcommands set and this subcommand not in it → no egress.
//  2. HostFlags set → egress iff one is present; its value is the target.
//  3. An @server operand (dig) → that server.
//  4. A first operand → that operand (host, URL, or recipient).
//  5. Always → egress with no operand at all (dig with no args queries the
//     root servers; nmap/ntpdate have defaults).
type NetTool struct {
	Aliases     []string
	Spec        Spec
	Subcommands Set      // egress only on these subcommands (svn, hg, docker)
	HostFlags   []string // egress only when one of these is given (mysql -h)
	HostPort    bool     // the operands are HOST PORT, reported as host:port (telnet h 25)
	Always      bool     // egress even with no operand
	Kind        string   // resource kind of the target for audit logs ("" = host)
	Action      string   // what the tool does with it ("" = connect)
	Secrets     []string // flags whose values are credentials (mysql -p), redacted in logs
}

func (n NetTool) SecretFlags() []string { return n.Secrets }

// Resources describes the egress target, or the operands when there is none.
func (n NetTool) Resources(p ParsedCommand) []Resource {
	kind, action := n.Kind, n.Action
	if kind == "" {
		kind = "host"
	}
	if action == "" {
		action = "connect"
	}
	if target, ok := n.Egress(p); ok {
		return []Resource{{Kind: kind, Action: action, Value: target}}
	}
	return operandResources(p, "operand", "", false)
}

func (n NetTool) Names() []string                { return n.Aliases }
func (n NetTool) Parse(a []string) ParsedCommand { return n.Spec.Parse(a) }
func (n NetTool) Egress(p ParsedCommand) (string, bool) {
	if len(n.Subcommands) > 0 && !n.Subcommands[p.Subcommand] {
		return "", false
	}
	if len(n.HostFlags) > 0 {
		if v, ok := p.FirstValue(n.HostFlags...); ok {
			return v, true
		}
		return "", false
	}
	for _, o := range p.Operands {
		if strings.HasPrefix(o, "@") && len(o) > 1 {
			return o[1:], true
		}
	}
	if len(p.Operands) > 0 {
		if n.HostPort {
			return strings.Join(p.Operands, ":"), true
		}
		return p.Operands[0], true
	}
	if n.Always {
		return n.Aliases[0], true
	}
	return "", false
}

// netTool is shorthand for a first-operand NetTool with the given value flags.
func netTool(names []string, valueFlags ...string) NetTool {
	return NetTool{Aliases: names, Spec: Spec{ValueFlags: NewSet(valueFlags...)}}
}

// queryTool / kindTool set the audit kind and action of a first-operand NetTool.
func queryTool(names []string, valueFlags ...string) NetTool {
	return kindTool("host", "query", names, valueFlags...)
}

func kindTool(kind, action string, names []string, valueFlags ...string) NetTool {
	n := netTool(names, valueFlags...)
	n.Kind, n.Action = kind, action
	return n
}

func names(n ...string) []string { return n }

var netTools = []Command{
	// DNS
	NetTool{Aliases: names("dig", "drill"), Spec: Spec{ValueFlags: NewSet("-p", "-b", "-f", "-q", "-t", "-c", "-x", "-y", "-k")}, Always: true, Action: "query"},
	queryTool(names("nslookup"), "-port", "-type", "-class", "-timeout", "-retry", "-querytype"),
	queryTool(names("host"), "-t", "-c", "-p", "-W", "-R", "-N", "-m"),
	queryTool(names("whois"), "-h", "--host", "-p", "--port", "-T"),
	// reachability / scanning
	kindTool("host", "probe", names("ping", "ping6"), "-c", "-i", "-W", "-w", "-s", "-t", "-I", "-l", "-p", "-Q", "-S", "-M"),
	kindTool("host", "probe", names("traceroute", "traceroute6", "tracepath", "mtr"), "-m", "-q", "-w", "-p", "-f", "-i", "-s", "-c", "-r", "-n"),
	NetTool{Aliases: names("nmap", "masscan"), Spec: Spec{ValueFlags: NewSet("-p", "-sV", "-oN", "-oX", "-oG", "-oA", "-iL", "-e", "-S", "-T", "--ports", "--rate")}, Always: true, Action: "scan"},
	queryTool(names("ssh-keyscan"), "-p", "-t", "-T", "-f"),
	NetTool{Aliases: names("ntpdate", "sntp", "rdate"), Spec: Spec{ValueFlags: NewSet("-p", "-t", "-K")}, Always: true, Action: "query"},
	// remote sessions and transfers
	NetTool{Aliases: names("telnet"), Spec: Spec{ValueFlags: NewSet("-l", "-e", "-n", "-b", "-S")}, HostPort: true, Kind: "socket"},
	netTool(names("ftp", "lftp", "tftp", "ncftp"), "-p", "-e", "-u", "-c", "-s"),
	kindTool("url", "fetch", names("aria2c", "axel", "fetch", "http", "https", "httpie"), "-o", "-d", "-x", "-s", "-n", "-a", "--out", "--dir", "--auth"),
	kindTool("url", "fetch", names("lynx", "w3m", "links", "elinks"), "-cfg", "-o", "-T", "-cookie_file"),
	// mail
	kindTool("recipient", "send", names("sendmail", "mail", "mailx", "msmtp", "mutt"), "-s", "-c", "-b", "-r", "-a", "-f", "-F", "-t", "-A"),
	// VCS and containers: only some subcommands reach out
	NetTool{Aliases: names("svn"), Spec: Spec{Subcommand: true, ValueFlags: NewSet("-r", "--revision", "--username", "--password", "--config-dir")},
		Subcommands: NewSet("checkout", "co", "export", "update", "up", "commit", "ci", "log", "info", "ls", "list", "cat", "switch", "sw", "merge", "diff", "import"), Kind: "repo", Action: "access"},
	NetTool{Aliases: names("hg"), Spec: Spec{Subcommand: true, ValueFlags: NewSet("-r", "--rev", "-b", "--branch", "-R", "--repository", "--config")},
		Subcommands: NewSet("clone", "pull", "push", "incoming", "in", "outgoing", "out", "identify", "id"), Kind: "repo", Action: "access"},
	NetTool{Aliases: names("docker", "podman", "nerdctl"), Spec: Spec{Subcommand: true, ValueFlags: NewSet("-H", "--host", "--context", "-c", "-l", "--log-level")},
		Subcommands: NewSet("pull", "push", "login", "logout", "search", "build", "run", "create", "manifest", "buildx", "compose"), Kind: "image", Action: "access"},
	// DB clients: local socket unless a host is given
	NetTool{Aliases: names("mysql", "mariadb", "mysqldump", "mysqladmin"), Spec: Spec{ValueFlags: NewSet("-h", "--host", "-P", "--port", "-u", "--user", "-p", "--password", "-e", "--execute", "-S", "--socket")},
		HostFlags: []string{"-h", "--host"}, Kind: "database", Secrets: []string{"-p", "--password"}},
	NetTool{Aliases: names("psql", "pg_dump", "pg_restore", "pg_isready"), Spec: Spec{ValueFlags: NewSet("-h", "--host", "-p", "--port", "-U", "--username", "-d", "--dbname", "-c", "--command", "-f", "--file")},
		HostFlags: []string{"-h", "--host"}, Kind: "database"},
	NetTool{Aliases: names("redis-cli"), Spec: Spec{ValueFlags: NewSet("-h", "-p", "-a", "-n", "-u", "-s")},
		HostFlags: []string{"-h", "-u"}, Kind: "database", Secrets: []string{"-a", "-u", "--pass", "--user"}},
	NetTool{Aliases: names("mongosh", "mongo"), Spec: Spec{ValueFlags: NewSet("--host", "--port", "-u", "--username", "-p", "--password", "--eval")},
		HostFlags: []string{"--host"}, Kind: "database", Secrets: []string{"-p", "--password"}},
}

// Gpg is a Builtin (offline signature checks are what installers need) that
// ALSO egresses on keyserver operations — so it is Networked, and the egress
// guard denies `gpg --recv-keys …` even when gpg itself is allow-listed.
type Gpg struct{}

var gpgSpec = Spec{ValueFlags: NewSet(
	"--keyserver", "--keyserver-options", "--recv-keys", "--search-keys", "--send-keys",
	"--fetch-keys", "--refresh-keys", "--locate-keys", "--auto-key-locate",
	"-o", "--output", "-r", "--recipient", "-u", "--local-user", "--homedir", "--status-fd", "--passphrase-file")}

var gpgNetOps = []string{"--recv-keys", "--search-keys", "--send-keys", "--fetch-keys", "--refresh-keys",
	"--locate-keys", "--locate-external-keys", "--auto-key-retrieve", "--recv", "--keyserver"}

func (Gpg) Names() []string                { return []string{"gpg", "gpg2", "gpgv"} }
func (Gpg) Parse(a []string) ParsedCommand { return gpgSpec.Parse(a) }
func (Gpg) builtin()                       {}
func (Gpg) Egress(p ParsedCommand) (string, bool) {
	if ks, ok := p.FlagValue("--keyserver"); ok && ks != "" {
		return ks, true
	}
	for _, op := range gpgNetOps {
		if p.HasFlag(op) {
			return op, true
		}
	}
	return "", false
}

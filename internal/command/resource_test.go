package command

import (
	"strings"
	"testing"
)

// TestDescribe pins the audit line for one representative of every source of
// resources: tagged params, Describers, NetTools, package managers, the
// Networked fallback, and the plain-operand fallback — including the piped
// forms where the resource is a stream, not a file.
func TestDescribe(t *testing.T) {
	cases := map[string]string{
		// tagged params, with stream fallbacks
		"curl -sSfL https://x/y -o out.tgz":                             "curl: fetch url https://x/y, write path out.tgz",
		"curl -s https://x/y":                                           "curl: fetch url https://x/y, write stdout",
		"curl -H 'Authorization: Bearer SECRET' https://x/y":            "curl: fetch url https://x/y, write stdout",
		"wget -O f https://a/b":                                         "wget: fetch url https://a/b, write path f",
		"openssl dgst -sha256 file":                                     "openssl: digest path file",
		"openssl dgst -sha256":                                          "openssl: digest stdin",
		"openssl enc -d -aes-256-cbc -in f.enc -out f.txt -pass pass:x": "openssl: decrypt path f.enc, write path f.txt",
		"openssl aes-256-cbc -k secret":                                 "openssl: encrypt stdin, write stdout",
		"openssl enc -base64 -in blob":                                  "openssl: encrypt path blob, write stdout",
		"openssl dgst -sha256 -sign key.pem -out f.sig f":               "openssl: sign path f, read key key.pem, write path f.sig",
		"openssl dgst -sha256 -verify pub.pem -signature f.sig f":       "openssl: verify path f, read key pub.pem",
		"openssl pkeyutl -decrypt -inkey priv.pem -in c.bin":            "openssl: decrypt path c.bin, read key priv.pem, write stdout",
		"openssl rsautl -sign -inkey k.pem -in f -out s":                "openssl: sign path f, read key k.pem, write path s",
		"openssl rand -hex 16":                                          "openssl: generate random 16, write stdout",
		"openssl passwd -6 hunter2":                                     "openssl: hash password, write stdout",
		"openssl s_client -connect h:443":                               "openssl: connect host h:443",
		"ssh -p 22 user@host uptime -a":                                 "ssh: connect host user@host, run command uptime, run command -a",
		"base64 -d payload":                                             "base64: read path payload",
		"base64 -d":                                                     "base64: read stdin",
		"chmod -R 755 a b":                                              "chmod: apply mode 755, modify path a, modify path b",
		"xattr -dr com.apple.quarantine payload":                        "xattr: delete attribute com.apple.quarantine, modify path payload",
		"xattr -p com.apple.quarantine f":                               "xattr: read attribute com.apple.quarantine, read path f",
		"chown root:root /etc/x":                                        "chown: apply owner root:root, modify path /etc/x",
		"setfacl -m u:bob:rx d":                                         "setfacl: add acl u:bob:rx, modify path d",
		// Describers
		"cat":                                    "cat: read stdin",
		"cat a b":                                "cat: read path a, read path b",
		"sha256sum":                              "sha256sum: read stdin",
		"grep -q pattern f":                      "grep: read path f",
		"grep pattern":                           "grep: read stdin",
		"sed -i s/a/b/ f":                        "sed: modify path f",
		"sed s/a/b/":                             "sed: read stdin",
		"awk '{print}' f":                        "awk: read path f",
		"tar -xzf uv.tgz -C /tmp/x":              "tar: read archive uv.tgz, chdir path /tmp/x",
		"tar -xz":                                "tar: read stdin",
		"tar -czf out.tgz dir":                   "tar: write archive out.tgz, read path dir",
		"find /tmp -name x -exec rm -rf {} ;":    "find: read path /tmp, run command rm -rf {}",
		"sh -c 'echo hi'":                        "sh: run script echo hi",
		"sh":                                     "sh: run stdin",
		"sh install.sh":                          "sh: run path install.sh",
		"perl -MLWP::Simple -e 'getstore(1)'":    "perl: load module LWP::Simple, run code getstore(1)",
		"perl":                                   "perl: run stdin",
		"python3 -m http.server 8000":            "python3: run module http.server",
		"python3 -c 'import requests'":           "python3: run code import requests, load module requests",
		"python3 -c 'print(1)'":                  "python3: run code print(1)",
		"python3 setup.py install":               "python3: run path setup.py",
		"python3":                                "python3: run stdin",
		"rsync -a ./src/ host:dst/":              "rsync: sync path ./src/, sync remote host:dst/",
		"scp f user@h:/tmp/":                     "scp: copy path f, copy remote user@h:/tmp/",
		"install -m 755 uv /usr/local/bin/uv":    "install: apply mode 755, read path uv, write path /usr/local/bin/uv",
		"gpg --verify f.asc f":                   "gpg: read path f.asc, read path f",
		"gpg --keyserver hkps://k --recv-keys X": "gpg: connect keyserver hkps://k",
		"git clone https://g/r":                  "git: clone repo https://g/r",
		"git status":                             "git",
		"nc -l 4444":                             "nc: listen socket 4444",
		// NetTools
		"dig @8.8.8.8 example.com": "dig: query host 8.8.8.8",
		"ping -c 1 10.0.0.1":       "ping: probe host 10.0.0.1",
		"telnet h 25":              "telnet: connect socket h:25",
		"docker pull alpine":       "docker: access image alpine",
		"docker ps":                "docker",
		"mysql -h db app":          "mysql: connect database db",
		"mail -s hi bob@example":   "mail: send recipient bob@example",
		"aria2c https://x/y":       "aria2c: fetch url https://x/y",
		// package managers
		"apt-get -y install docker-ce curl": "apt-get: install package docker-ce, install package curl",
		"apt-get -qq update":                "apt-get: update packages",
		"pip install -r req.txt requests":   "pip: install package requests",
		"pip install https://x/p.whl":       "pip: install url https://x/p.whl",
		"dpkg -i ./pkg.deb":                 "dpkg: manage path ./pkg.deb",
		"pacman -Syu":                       "pacman: -S packages",
		// fallbacks
		"echo hi there": "echo: operand hi, operand there",
		"uname -m":      "uname",
		"frobnicate x":  "frobnicate: operand x",
	}
	for cmdline, want := range cases {
		args := splitShellish(cmdline)
		if got := Parse(args).Describe(); got != want {
			t.Errorf("%s\n  got  %q\n  want %q", cmdline, got, want)
		}
	}
}

// splitShellish splits a test command line on spaces, honouring single quotes.
func splitShellish(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	for _, r := range s {
		switch {
		case r == '\'':
			inQ = !inQ
		case r == ' ' && !inQ:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func TestPackageManagerEgress(t *testing.T) {
	cases := []struct {
		args       []string
		wantTarget string
		networked  bool
	}{
		{[]string{"apt-get", "-y", "-qq", "install", "docker-ce"}, "install", true}, // flags before the subcommand
		{[]string{"apt-get", "update"}, "update", true},
		{[]string{"apt-cache", "policy", "docker-ce"}, "", false},
		{[]string{"dpkg", "-i", "./x.deb"}, "", false},
		{[]string{"rpm", "-i", "https://x/p.rpm"}, "https://x/p.rpm", true},
		{[]string{"rpm", "-qa"}, "", false},
		{[]string{"yum", "-y", "install", "x"}, "install", true},
		{[]string{"apk", "add", "--no-cache", "curl"}, "add", true},
		{[]string{"apk", "del", "curl"}, "del", true}, // del is in the set: apk may refetch the index
		{[]string{"pacman", "-Syu"}, "-S", true},
		{[]string{"pacman", "-Q"}, "", false},
		{[]string{"brew", "install", "uv"}, "install", true},
		{[]string{"brew", "list"}, "", false},
		{[]string{"pip", "install", "requests"}, "install", true},
		{[]string{"pip", "freeze"}, "", false},
		{[]string{"uv", "python", "list"}, "python", true},
		{[]string{"uv", "--version"}, "", false},
		{[]string{"npm", "ci"}, "ci", true},
		{[]string{"npm", "run", "build"}, "", false},
		{[]string{"cargo", "build"}, "build", true},
		{[]string{"go", "get", "example.com/m"}, "get", true},
		{[]string{"go", "fmt"}, "", false},
		{[]string{"cpanm", "Foo::Bar"}, "Foo::Bar", true},
		{[]string{"cpanm"}, "", false},
	}
	for _, c := range cases {
		p := Parse(c.args)
		if _, ok := p.Command().(PackageManager); !ok {
			t.Errorf("%s is not a PackageManager", c.args[0])
			continue
		}
		target, networked := p.Egress()
		if networked != c.networked || target != c.wantTarget {
			t.Errorf("%v: Egress = %q,%v; want %q,%v", c.args, target, networked, c.wantTarget, c.networked)
		}
	}
	// The subcommand-after-flags fix also helps git.
	if p := Parse([]string{"git", "-C", "/x", "clone", "https://g/r"}); p.Subcommand != "clone" {
		t.Errorf("git -C dir clone: subcommand = %q", p.Subcommand)
	}
}

func TestRedact(t *testing.T) {
	c := Redact(Parse([]string{"curl", "-H", "Authorization: Bearer tok", "-b", "sid=1", "-d", "pw=x", "-A", "ua", "https://x"}).TypedParams()).(CurlParams)
	if c.Headers[0] != Redacted || c.Cookies[0] != Redacted || len(c.Data) != 1 || c.Data[0] != Redacted || c.UserAgent != "ua" {
		t.Errorf("curl redaction wrong: %+v", c)
	}
	if got := c.String(); strings.Contains(got, "tok") || !strings.Contains(got, "-H REDACTED") {
		t.Errorf("rendered curl leaks: %q", got)
	}
	// Generic form: global secret flags and a NetTool's own.
	g := Redact(Parse([]string{"mysql", "-h", "db", "-p", "hunter2", "--password", "x", "app"}).TypedParams()).(ParsedCommand)
	if got := g.String(); strings.Contains(got, "hunter2") || !strings.Contains(got, "-h db") {
		t.Errorf("mysql redaction wrong: %q", got)
	}
	if got := Redact(Parse([]string{"frob", "--token=abc", "-x", "keep"}).TypedParams()).String(); strings.Contains(got, "abc") || !strings.Contains(got, "-x keep") {
		t.Errorf("generic redaction wrong: %q", got)
	}
	// openssl: passphrases and raw keys are fields; -hmac lives in Rest and is still redacted.
	o := Redact(Parse([]string{"openssl", "enc", "-aes-256-cbc", "-pass", "pass:hunter2", "-K", "00ff", "-in", "f"}).TypedParams()).(OpensslParams)
	if o.PassIn != Redacted || o.Key != Redacted || o.In != "f" || strings.Contains(o.String(), "hunter2") {
		t.Errorf("openssl redaction wrong: %+v / %s", o, o)
	}
	h := Redact(Parse([]string{"openssl", "dgst", "-sha256", "-hmac", "topsecret", "f"}).TypedParams()).(OpensslParams)
	if got := h.String(); strings.Contains(got, "topsecret") || !strings.Contains(got, "-hmac REDACTED") {
		t.Errorf("rest redaction wrong: %q", got)
	}
	d := Redact(Parse([]string{"docker", "login", "--username", "bob", "--password", "hunter2", "registry.example"}).TypedParams()).(DockerLoginParams)
	if d.Password != Redacted || d.Username != "bob" {
		t.Errorf("docker login redaction wrong: %+v", d)
	}
	if got := d.String(); strings.Contains(got, "hunter2") || !strings.Contains(got, "--password REDACTED") {
		t.Errorf("docker password redaction wrong: %q", got)
	}
	// The as-run argv is redacted in place, both value forms.
	if got := strings.Join(Parse([]string{"mysql", "-h", "db", "-p", "hunter2", "--password=x", "app"}).RedactedArgv(), " "); got != "mysql -h db -p REDACTED --password=REDACTED app" {
		t.Errorf("RedactedArgv = %q", got)
	}
	// Non-secret params pass through untouched.
	if b := Redact(Parse([]string{"base64", "-d", "f"}).TypedParams()).(Base64Params); !b.Decode || b.File != "f" {
		t.Errorf("base64 params altered: %+v", b)
	}
}

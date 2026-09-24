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

func TestCurlDataFlags(t *testing.T) {
	// Each data flag keeps its own field, so a round trip keeps its semantics:
	// --data-binary must not come back as -d (which strips newlines).
	c := curlParamsFrom(Parse([]string{"curl", "-d", "a=1", "--data-raw", "@literal",
		"--data-binary", "@body.bin", "--data-urlencode", "q=a b", "https://x"}))
	if len(c.Data) != 1 || len(c.DataRaw) != 1 || len(c.DataBinary) != 1 || len(c.DataURLEncode) != 1 {
		t.Fatalf("data fields wrong: %+v", c)
	}
	if got, want := c.String(), `curl -d a=1 --data-raw @literal --data-binary @body.bin --data-urlencode 'q=a b' https://x`; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	parts := c.BodyParts()
	if len(parts) != 4 {
		t.Fatalf("BodyParts() = %d parts, want 4", len(parts))
	}
	if p := parts[0]; p.Value != "a=1" || p.File || !p.StripNewlines {
		t.Errorf("-d part wrong: %+v", p)
	}
	if p := parts[1]; p.Value != "@literal" || p.File { // raw: @ is literal
		t.Errorf("--data-raw part wrong: %+v", p)
	}
	if p := parts[2]; p.Value != "body.bin" || !p.File || p.StripNewlines {
		t.Errorf("--data-binary part wrong: %+v", p)
	}
	if p := parts[3]; p.Prefix != "q=" || p.Value != "a b" || !p.URLEncode {
		t.Errorf("--data-urlencode part wrong: %+v", p)
	}

	// Any body makes the request a POST unless -X overrides.
	if r := (Curl{}).Request(Parse([]string{"curl", "--data-raw", "x", "https://x"})); r.Method != "POST" || len(r.Body) != 1 {
		t.Errorf("Request with body wrong: %+v", r)
	}
}

func TestCurlUserIsRedacted(t *testing.T) {
	argv := strings.Join(Parse([]string{"curl", "-u", "alice:hunter2", "https://x"}).RedactedArgv(), " ")
	if strings.Contains(argv, "hunter2") || !strings.Contains(argv, "-u REDACTED") {
		t.Errorf("curl -u leaks credentials: %q", argv)
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

func TestDockerParams(t *testing.T) {
	p := Parse([]string{"docker", "--context", "remote", "run", "--name", "web", "--rm",
		"alpine:3.20", "sh", "-c", "echo hi"})
	d, ok := p.TypedParams().(DockerRunParams)
	if !ok {
		t.Fatalf("TypedParams() = %T, want DockerRunParams", p.TypedParams())
	}
	if d.Name != "docker" || d.Context != "remote" || d.Subcommand != "run" || d.Image != "alpine:3.20" {
		t.Errorf("fields wrong: %+v", d)
	}
	if d.ContainerName != "web" || !d.Remove || len(d.Rest) != 0 {
		t.Errorf("run flags not typed: %+v", d)
	}
	if got, want := strings.Join(d.Arguments, " "), "sh -c echo hi"; got != want {
		t.Errorf("Arguments = %q, want %q", got, want)
	}
	if got, want := d.String(), "docker --context remote run --name web --rm alpine:3.20 sh -c 'echo hi'"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	// The compatible CLI spelling survives a typed round trip.
	podman := Parse([]string{"podman", "pull", "quay.io/acme/app:latest"}).TypedParams().(DockerParams)
	if got, want := podman.String(), "podman pull quay.io/acme/app:latest"; got != want {
		t.Errorf("Podman String() = %q, want %q", got, want)
	}

	// A value-taking run flag must not become the image, and flags for the
	// command inside the container must remain trailing arguments.
	run := Parse([]string{"nerdctl", "run", "-p", "8080:80", "nginx", "nginx", "-g", "daemon off;"}).TypedParams().(DockerRunParams)
	if run.Image != "nginx" || strings.Join(run.Arguments, " ") != "nginx -g daemon off;" {
		t.Errorf("Nerdctl run params wrong: %+v", run)
	}
	if len(run.Publish) != 1 || run.Publish[0] != "8080:80" {
		t.Errorf("Publish = %v, want [8080:80]", run.Publish)
	}

	// Global short options are typed, while the same spelling after `run`
	// remains a subcommand-specific option.
	global := Parse([]string{"docker", "-c", "remote", "ps"}).TypedParams().(DockerParams)
	if global.Context != "remote" || len(global.Rest) != 0 {
		t.Errorf("global -c params wrong: %+v", global)
	}
	cpu := Parse([]string{"docker", "run", "-c", "512", "alpine"}).TypedParams().(DockerRunParams)
	if cpu.Context != "" || strings.Join(cpu.Rest, " ") != "-c 512" || cpu.Image != "alpine" {
		t.Errorf("run -c params wrong: %+v", cpu)
	}
}

func TestDockerFamilyParams(t *testing.T) {
	// run: what the container mounts, exposes and runs as is typed.
	r := Parse([]string{"docker", "run", "--rm", "-v", "/host:/data", "--mount", "type=bind,src=/,dst=/mnt",
		"-e", "TOKEN=x", "--network", "host", "--privileged", "-u", "root", "--cap-add", "SYS_ADMIN",
		"alpine", "sh"}).TypedParams().(DockerRunParams)
	if strings.Join(r.Volumes, " ") != "/host:/data" || len(r.Mounts) != 1 || len(r.Env) != 1 ||
		r.Network != "host" || !r.Privileged || r.User != "root" || strings.Join(r.CapAdd, " ") != "SYS_ADMIN" {
		t.Errorf("run params wrong: %+v", r)
	}
	if r.Image != "alpine" || strings.Join(r.Arguments, " ") != "sh" {
		t.Errorf("run image/arguments wrong: %+v", r)
	}

	// build: -t is the image tag (a value), --pull a bool, first operand the context.
	b := Parse([]string{"docker", "build", "-t", "app:latest", "-f", "Dockerfile.ci",
		"--build-arg", "V=1", "--pull", "."}).TypedParams().(DockerBuildParams)
	if strings.Join(b.Tags, " ") != "app:latest" || b.File != "Dockerfile.ci" ||
		strings.Join(b.BuildArgs, " ") != "V=1" || !b.Pull || b.Path != "." {
		t.Errorf("build params wrong: %+v", b)
	}
	// Rendering uses the long canonical spelling, so audit lines self-describe.
	if got, want := b.String(), "docker build --file Dockerfile.ci --tag app:latest --build-arg V=1 --pull ."; got != want {
		t.Errorf("build String() = %q, want %q", got, want)
	}

	// exec: who runs what in which container.
	e := Parse([]string{"docker", "exec", "-u", "root", "-w", "/app", "web", "ls", "-la"}).TypedParams().(DockerExecParams)
	if e.User != "root" || e.Workdir != "/app" || e.Container != "web" || strings.Join(e.Arguments, " ") != "ls -la" {
		t.Errorf("exec params wrong: %+v", e)
	}

	// ps -l is --latest, a bool: it must not swallow the next argument.
	ps := Parse([]string{"docker", "ps", "-l", "-q"}).TypedParams().(DockerParams)
	if got, want := strings.Join(ps.Rest, " "), "-l -q"; got != want {
		t.Errorf("ps Rest = %q, want %q", got, want)
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

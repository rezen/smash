package command

// DockerCommand models the Docker-compatible container CLIs. Docker, Podman,
// and Nerdctl share the command shape that matters here: global daemon options,
// a subcommand, and (for networked operations) an image or registry target.
//
// The grammar puts global options before the subcommand, so Parse splits the
// argv there and parses each half with its own spec. That keeps the overloaded
// short options unambiguous by position: `-c` is --context before the
// subcommand and --cpu-shares after `run`, with no fix-ups afterwards.
//
// Each subcommand family with flags worth reading by name has its own params
// struct (DockerRunParams, DockerBuildParams, …); the rest share the generic
// DockerParams. Every struct embeds DockerGlobals.
type DockerCommand struct{}

var dockerNetworkSubcommands = NewSet(
	"pull", "push", "login", "logout", "search", "build", "run", "create",
	"manifest", "buildx", "compose",
)

// DockerGlobals are the daemon-level options accepted before any subcommand,
// embedded by every docker params struct.
type DockerGlobals struct {
	Name      string   // the CLI spelling used: docker, podman or nerdctl
	Config    string   `flag:"--config"`
	Context   string   `flag:"--context"` // a global -c binds here (see Parse)
	Debug     bool     `flag:"--debug,-D"`
	Hosts     []string `flag:"--host,-H"`
	LogLevel  string   `flag:"--log-level"` // a global -l binds here (see Parse)
	TLS       bool     `flag:"--tls"`
	TLSVerify bool     `flag:"--tlsverify"`
	TLSCACert string   `flag:"--tlscacert"`
	TLSCert   string   `flag:"--tlscert"`
	TLSKey    string   `flag:"--tlskey"`
}

// dockerGlobalShorts are the global aliases whose spelling collides with
// subcommand options; Parse rebinds them to their long form so the structs
// above never see an ambiguous name.
var dockerGlobalShorts = map[string]string{"-c": "--context", "-l": "--log-level"}

// DockerParams is the typed view of the subcommands that need no fields of
// their own (pull, push, ps, images, compose, …).
type DockerParams struct {
	DockerGlobals
	Subcommand string   `role:"subcommand"`
	Rest       []string `role:"rest" secret:"--password"`
	Image      string   `operand:"first"`
	Arguments  []string `operand:"rest"`
}

// DockerRunParams models run/create: what the container mounts, exposes and
// runs as is typed; the resource-limit knobs stay in Rest.
type DockerRunParams struct {
	DockerGlobals
	Subcommand    string   `role:"subcommand"` // run or create
	ContainerName string   `flag:"--name"`
	Detach        bool     `flag:"--detach,-d"`
	Interactive   bool     `flag:"--interactive,-i"`
	TTY           bool     `flag:"--tty,-t"`
	Remove        bool     `flag:"--rm"`
	Privileged    bool     `flag:"--privileged"`
	ReadOnly      bool     `flag:"--read-only"`
	Env           []string `flag:"--env,-e"`
	EnvFiles      []string `flag:"--env-file"`
	Volumes       []string `flag:"--volume,-v"`
	Mounts        []string `flag:"--mount"`
	Publish       []string `flag:"--publish,-p"`
	Network       string   `flag:"--network"`
	User          string   `flag:"--user,-u"`
	Workdir       string   `flag:"--workdir,-w"`
	Entrypoint    string   `flag:"--entrypoint"`
	Pull          string   `flag:"--pull"` // always | missing | never
	CapAdd        []string `flag:"--cap-add"`
	CapDrop       []string `flag:"--cap-drop"`
	SecurityOpt   []string `flag:"--security-opt"`
	Devices       []string `flag:"--device"`
	Rest          []string `role:"rest"`
	Image         string   `operand:"first"`
	Arguments     []string `operand:"rest"` // the command run inside the container
}

// DockerBuildParams models build/buildx. Unlike run's, its --pull and -t are
// a bool and the image tag.
type DockerBuildParams struct {
	DockerGlobals
	Subcommand string   `role:"subcommand"` // build or buildx
	File       string   `flag:"--file,-f"`
	Tags       []string `flag:"--tag,-t"`
	BuildArgs  []string `flag:"--build-arg"`
	Target     string   `flag:"--target"`
	Platform   string   `flag:"--platform"`
	Pull       bool     `flag:"--pull"`
	NoCache    bool     `flag:"--no-cache"`
	Secrets    []string `flag:"--secret"`
	SSH        []string `flag:"--ssh"`
	Output     string   `flag:"--output,-o"`
	Rest       []string `role:"rest"`
	Path       string   `operand:"first"` // the build context
	Arguments  []string `operand:"rest"`
}

// DockerLoginParams models login. Prefer --password-stdin; a --password value
// is a secret field and redacts.
type DockerLoginParams struct {
	DockerGlobals
	Subcommand    string   `role:"subcommand"`
	Username      string   `flag:"--username,-u"`
	Password      string   `flag:"--password,-p" secret:"true"`
	PasswordStdin bool     `flag:"--password-stdin"`
	Rest          []string `role:"rest"`
	Registry      string   `operand:"first"`
}

// DockerExecParams models exec: who runs what in which container.
type DockerExecParams struct {
	DockerGlobals
	Subcommand  string   `role:"subcommand"`
	Detach      bool     `flag:"--detach,-d"`
	Interactive bool     `flag:"--interactive,-i"`
	TTY         bool     `flag:"--tty,-t"`
	Env         []string `flag:"--env,-e"`
	User        string   `flag:"--user,-u"`
	Workdir     string   `flag:"--workdir,-w"`
	Rest        []string `role:"rest"`
	Container   string   `operand:"first"`
	Arguments   []string `operand:"rest"`
}

// dockerValueFlags are the unmodelled long options that take a value, kept so
// no family's spec mistakes an option argument for the image. Options a family
// models as fields also appear as value flags via its struct tags.
var dockerValueFlags = []string{
	"--add-host", "--annotation", "--attach", "--build-arg", "--build-context",
	"--cache-from", "--cache-to", "--cap-add", "--cap-drop", "--cgroup-parent",
	"--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period",
	"--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
	"--device", "--device-cgroup-rule", "--dns", "--dns-option", "--dns-search",
	"--domainname", "--env", "--env-file", "--entrypoint", "--expose",
	"--file", "--filter", "--format", "--gpus", "--hostname",
	"--init-path", "--ip", "--ip6", "--ipc", "--isolation", "--label", "--label-file",
	"--link", "--link-local-ip", "--memory", "--memory-reservation",
	"--memory-swap", "--memory-swappiness", "--mount", "--name", "--network",
	"--network-alias", "--output", "--password", "--pid", "--platform",
	"--progress", "--publish", "--restart", "--runtime", "--secret",
	"--security-opt", "--shm-size", "--ssh", "--stop-signal", "--stop-timeout",
	"--storage-opt", "--sysctl", "--tag", "--target", "--tmpfs", "--ulimit",
	"--user", "--username", "--userns", "--volume", "--volumes-from", "--workdir",
}

// The per-family specs. Short options with command-specific meanings are
// listed per family — `build -t NAME` takes a value while `run -t IMAGE` does
// not — and run's -c/-l are --cpu-shares/--label, not the global aliases.
var (
	dockerBaseSpec    = specOf(DockerParams{}, false, "-c", "-l")
	dockerGlobalSpec  = specOf(DockerGlobals{}, false, "-c", "-l")
	dockerRunSpec     = stopAtOperand(specOf(DockerRunParams{}, false, append([]string{"-a", "-h", "-m", "-c", "-l"}, dockerValueFlags...)...))
	dockerBuildSpec   = stopAtOperand(specOf(DockerBuildParams{}, false, append([]string{"-m"}, dockerValueFlags...)...))
	dockerLoginSpec   = stopAtOperand(specOf(DockerLoginParams{}, false, dockerValueFlags...))
	dockerExecSpec    = stopAtOperand(specOf(DockerExecParams{}, false, dockerValueFlags...))
	dockerComposeSpec = stopAtOperand(specOf(DockerParams{}, false, append([]string{"-f", "-p"}, dockerValueFlags...)...))
	dockerListSpec    = stopAtOperand(specOf(DockerParams{}, false, append([]string{"-f"}, dockerValueFlags...)...))
	dockerGenericSpec = stopAtOperand(specOf(DockerParams{}, false, dockerValueFlags...))
)

func dockerSpecFor(subcommand string) Spec {
	switch subcommand {
	case "run", "create":
		return dockerRunSpec
	case "build", "buildx":
		return dockerBuildSpec
	case "login":
		return dockerLoginSpec
	case "exec":
		return dockerExecSpec
	case "compose":
		return dockerComposeSpec
	case "images", "ps":
		return dockerListSpec
	}
	return dockerGenericSpec
}

func (DockerCommand) Names() []string { return []string{"docker", "podman", "nerdctl"} }

// Parse first locates the subcommand, then parses the argv's two halves with
// the global and the family spec, rebinding the global short aliases to their
// long names as the flag maps merge.
func (DockerCommand) Parse(a []string) ParsedCommand {
	base := dockerBaseSpec.Parse(a)
	if len(a) == 0 {
		return base
	}
	end := base.subIndex
	if base.Subcommand == "" {
		end = len(a)
	}
	globals := dockerGlobalSpec.Parse(a[:end])
	p := dockerSpecFor(base.Subcommand).Parse(append([]string{a[0]}, a[end:]...))
	for name, vals := range globals.Flags {
		if long, ok := dockerGlobalShorts[name]; ok {
			name = long
		}
		p.Flags[name] = append(vals, p.Flags[name]...)
	}
	p.raw = a
	p.subIndex = base.subIndex
	return p
}

func (DockerCommand) Params(p ParsedCommand) Params {
	switch p.Subcommand {
	case "run", "create":
		return dockerRunParamsFrom(p)
	case "build", "buildx":
		return dockerBuildParamsFrom(p)
	case "login":
		return dockerLoginParamsFrom(p)
	case "exec":
		return dockerExecParamsFrom(p)
	}
	return dockerParamsFrom(p)
}

func dockerParamsFrom(p ParsedCommand) (d DockerParams) { bind(p, &d); d.Name = p.Name; return d }
func dockerRunParamsFrom(p ParsedCommand) (d DockerRunParams) {
	bind(p, &d)
	d.Name = p.Name
	return d
}
func dockerBuildParamsFrom(p ParsedCommand) (d DockerBuildParams) {
	bind(p, &d)
	d.Name = p.Name
	return d
}
func dockerLoginParamsFrom(p ParsedCommand) (d DockerLoginParams) {
	bind(p, &d)
	d.Name = p.Name
	return d
}
func dockerExecParamsFrom(p ParsedCommand) (d DockerExecParams) {
	bind(p, &d)
	d.Name = p.Name
	return d
}

// dockerName defaults a rendered invocation to the docker spelling.
func dockerName(name string) string {
	if name == "" {
		return "docker"
	}
	return name
}

func (d DockerParams) Args() []string      { return render(dockerName(d.Name), d, false) }
func (d DockerParams) String() string      { return JoinArgs(d.Args()) }
func (d DockerRunParams) Args() []string   { return render(dockerName(d.Name), d, false) }
func (d DockerRunParams) String() string   { return JoinArgs(d.Args()) }
func (d DockerBuildParams) Args() []string { return render(dockerName(d.Name), d, false) }
func (d DockerBuildParams) String() string { return JoinArgs(d.Args()) }
func (d DockerLoginParams) Args() []string { return render(dockerName(d.Name), d, false) }
func (d DockerLoginParams) String() string { return JoinArgs(d.Args()) }
func (d DockerExecParams) Args() []string  { return render(dockerName(d.Name), d, false) }
func (d DockerExecParams) String() string  { return JoinArgs(d.Args()) }

// Egress preserves the container model's previous behavior: only operations
// that can consult a registry are networked, and their first operand is the
// image/registry target.
func (DockerCommand) Egress(p ParsedCommand) (string, bool) {
	if !dockerNetworkSubcommands[p.Subcommand] || len(p.Operands) == 0 || p.Operands[0] == "" {
		return "", false
	}
	return p.Operands[0], true
}

// Resources keeps non-networked operands visible while describing registry
// operations as image access, matching the former NetTool representation.
func (d DockerCommand) Resources(p ParsedCommand) []Resource {
	if target, networked := d.Egress(p); networked {
		return []Resource{{Kind: "image", Action: "access", Value: target}}
	}
	return operandResources(p, "operand", "", false)
}

// Docker login accepts a password on the command line. Prefer
// --password-stdin, but ensure the long value form is redacted if encountered.
// -p is deliberately excluded because it means --publish for run/create.
func (DockerCommand) SecretFlags() []string { return []string{"--password"} }

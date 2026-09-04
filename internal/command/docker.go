package command

// DockerCommand models the Docker-compatible container CLIs. Docker, Podman,
// and Nerdctl share the command shape that matters here: global daemon options,
// a subcommand, and (for networked operations) an image or registry target.
type DockerCommand struct{}

var dockerNetworkSubcommands = NewSet(
	"pull", "push", "login", "logout", "search", "build", "run", "create",
	"manifest", "buildx", "compose",
)

// dockerValueFlags are long subcommand options whose following argument must
// not be mistaken for the image. Short options with command-specific meanings
// are added by dockerSpecFor below.
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

var dockerBaseSpec = specOf(DockerParams{}, false, "-c", "-l")

// dockerSpecFor avoids treating overloaded short flags uniformly. In
// particular, `build -t NAME` takes a value while `run -t IMAGE` does not.
func dockerSpecFor(subcommand string) Spec {
	values := append([]string{}, dockerValueFlags...)
	values = append(values, "-c", "-l") // global --context / --log-level aliases
	switch subcommand {
	case "run", "create":
		values = append(values, "-a", "-e", "-h", "-m", "-p", "-u", "-v", "-w", "--pull")
	case "build", "buildx":
		values = append(values, "-f", "-m", "-o", "-t")
	case "login":
		values = append(values, "-p", "-u")
	case "compose":
		values = append(values, "-f", "-p")
	case "exec":
		values = append(values, "-e", "-u", "-w")
	case "images", "ps":
		values = append(values, "-f")
	}
	return stopAtOperand(specOf(DockerParams{}, false, values...))
}

func (DockerCommand) Names() []string { return []string{"docker", "podman", "nerdctl"} }
func (DockerCommand) Parse(a []string) ParsedCommand {
	// First identify the subcommand using only global options, then parse again
	// with that subcommand's value-taking short flags.
	base := dockerBaseSpec.Parse(a)
	return dockerSpecFor(base.Subcommand).Parse(a)
}
func (DockerCommand) Params(p ParsedCommand) Params { return dockerParamsFrom(p) }

// Egress preserves the container model's previous behavior: only operations
// that can consult a registry are networked, and their first operand is the
// image/registry target.
func (DockerCommand) Egress(p ParsedCommand) (string, bool) {
	d := dockerParamsFrom(p)
	if !dockerNetworkSubcommands[d.Subcommand] || d.Image == "" {
		return "", false
	}
	return d.Image, true
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

# Go API

The CLI is a client of `internal/sandbox` and `internal/command`. These are
currently internal packages, so the examples describe embedding within this
module rather than a versioned public Go module API.

## Configure and run

`sandbox.NewConfig` supplies the default network policy, command allow-list,
and sensitive-command list. Its fields can then be widened or replaced:

```go
cfg := sandbox.NewConfig(root, home, env)
cfg.Allowed = cfg.Allowed.With("python3")
cfg.Strict = true
cfg.Network.AllowedPrefixes = []string{"https://internal.example/"}
cfg.Network.InjectHeaders = map[string]string{
	"Authorization": "Bearer …",
}
cfg.Emulation = sandbox.Emulation{
	UnameOS: "Linux",
	Files: map[string]string{
		"/etc/os-release": "ID=ubuntu\n",
	},
}
cfg.Timeout = 30 * time.Second
cfg.Auditor = sandbox.TextAuditor(os.Stderr)
cfg.AuditData = 4096

err := sandbox.Run(cfg, "install.sh", script)
```

The caller is responsible for preparing the root, home, environment, script
contents, and any lifecycle behavior that the CLI normally handles.

## Variables and assignments

`RunVars` executes a script and returns its final variable table. This exposes
values resolved by the path the installer actually took:

```go
vars, err := sandbox.RunVars(cfg, "install.sh", script)
fmt.Println(vars["ARTIFACT_DOWNLOAD_URLS"].String())
```

`Assignments` instead walks the syntax tree without executing it. It returns
each assignment as written and identifies values that require no expansion:

```go
assignments, err := sandbox.Assignments("install.sh", script)
// {Name:APP_NAME Value:uv Line:26 Static:true}
// {Name:ARTIFACT_DOWNLOAD_URLS Value:"$UV_DOWNLOAD_URL" Line:28}
```

## Disable commands

Disabled commands are checked after wrapper resolution and before mocks:

```go
cfg.Disable("rm", "rmdir")
```

This applies equally to direct execution, `sudo rm`, `find -exec rm`, nested
`sh -c`, and shell scripts installed below the run root.

`cfg.AllowSudo = true` makes credential probes succeed but does not elevate the
inner command.

## Mock responses

A mock selects a parsed invocation, returns stdout, stderr, and an exit code,
and records its calls:

```go
uname := cfg.Mock(
	sandbox.MatchArgs("uname", "-s"),
	"Linux\n", "", 0,
)

cfg.Mock(
	sandbox.MatchName("curl").And(
		sandbox.MatchResource("url", "https://releases.astral.sh/*"),
	),
	"", "", 0,
)

cfg.Mock(
	sandbox.MatchGlob("frobnicate *"),
	"", "frobnicate: boom\n", 3,
)

cfg.MockFunc(
	sandbox.MatchPrefix("version"),
	func(p command.ParsedCommand) (string, string, int) {
		return "v" + p.Operands[0] + "\n", "", 0
	},
)

fmt.Println(uname.Called())
fmt.Println(uname.Calls()[0].TypedParams())
```

Matchers are available for command names, exact argv, argv prefixes, complete
command-line globs, resource kind/value pairs, and arbitrary predicates. `And`
and `Or` compose them. Mocks run before the network and command allow-list, but
the disable list takes precedence.

## Command parsing

`internal/command` is independent of the shell interpreter. It can parse and
inspect argv without executing anything:

```go
p := command.Parse([]string{"curl", "-fsSL", "https://example.com/x"})
fmt.Println(p.String())
fmt.Println(p.TypedParams())
fmt.Println(p.Egress())
```

The parsed form also exposes resources, file changes where supported, wrapper
resolution, and redaction. See the [architecture reference](architecture.md)
for the capability interfaces behind these operations.

## Custom auditing

Set `Config.Auditor` to any `sandbox.Auditor` implementation. An auditor that
also implements `OpenAuditor` receives shell-controlled reads, writes, appends,
redirections, and sourced files.

`sandbox.TextAuditor` emits the standard YAML stream. Pass
`sandbox.ShortPaths(cfg)` to abbreviate paths below the configured root in the
rendered output.

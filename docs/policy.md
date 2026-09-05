# Policy reference

A policy file makes a run reviewable and repeatable. Generate a commented file
containing every supported key with:

```bash
smash -init-policy policy.yaml
smash -policy policy.yaml
```

The generated template is a no-op until edited. `smash` refuses to overwrite an
existing template and rejects unknown YAML keys so a misspelled rule cannot be
silently ignored.

## Complete example

```yaml
script: fixtures/fly.sh
args: [--non-interactive]
root: sandbox
timeout: 2m
strict: false
allow-sudo: false
allow-in-root: false

env:
  NO_COLOR: "1"

audit:
  path: fly-audit.yaml
  data: 200

commands:
  allow: [python3]
  disable: [rm, rmdir]
  sensitive: [ssh]
  replace: false

network:
  urls:
    - https://api.fly.io/
    - https://github.com/superfly/
    - https://release-assets.githubusercontent.com
  github: false
  git-hosts: [github.com]
  methods: [GET, HEAD]
  max-response: 200MiB
  max-request: 8MiB
  timeout: 60s
  dns-server: 9.9.9.9:53
  headers:
    Authorization: Bearer REDACTED

emulation:
  uname-os: Linux
  uname-arch: x86_64
  files:
    /etc/os-release: |
      ID=ubuntu

mocks:
  - match: {args: [uname, -s]}
    stdout: "Linux\n"
  - match:
      name: [curl, wget]
      resource: {kind: url, value: "https://releases.astral.sh/*"}
    stdout: ""
  - match: {glob: "frobnicate *"}
    stderr: "frobnicate: boom\n"
    exit: 3
  - match: {prefix: [git, clone]}
    stdout: "cloned\n"
```

## Run settings

| Key | Meaning |
|---|---|
| `script` | Local path or HTTP(S) URL to execute |
| `args` | Positional parameters for the script |
| `root` | Directory recreated for the run |
| `timeout` | Wall-time limit for the complete script |
| `strict` | Deny commands that are not allow-listed |
| `allow-sudo` | Answer sudo/doas credential probes without escalating commands |
| `allow-in-root` | Permit native executables below the root; an explicit unsafe capability |
| `posix` | Run the script as POSIX `sh` rather than Bash mode |
| `env` | Environment entries layered over the runner's defaults |

Changing `HOME`, `TMPDIR`, `PATH`, `SHELL`, or related environment entries can
weaken or break the intended root behavior. Treat those replacements as policy
changes, not ordinary application configuration.

## Audit settings

`audit.path` is `-` for stderr, an empty string to disable the audit stream, or
a file path. `audit.data` is the maximum number of bytes captured separately
from each command's stdin and stdout. A value of zero records metadata and
resources without payload data.

The YAML stream uses one sequence item per command or shell-open event. Its
fields include the normalized command, typed parameters, resources, file
changes, wrappers, exit status, duration, error or policy-denial reason, and
optional captured data. Secrets recognized by the command model are redacted.

## Command settings

- `allow` widens the default allow-list. It is also how a sensitive command
  such as `python3` or real `git` is deliberately permitted. The exact `git
  --version` availability probe remains usable without granting Git.
- `disable` is an unconditional deny-list. It applies after wrappers are
  resolved, so it also catches forms such as `sudo rm`, `find -exec rm`, and
  `sh -c 'rm …'`. A disabled command cannot be restored by a mock.
- `sensitive` widens the default sensitive list. Sensitive commands are denied
  even when non-strict mode would run an ordinary unlisted command.
- `replace: true` makes `allow` and `sensitive` replace their built-in lists
  instead of extending them. `disable` is always additive.

## Network settings

`urls` replaces the prefixes available to in-process `curl` and `wget`.
Matching is structural: schemes and hosts must match exactly, explicit ports
must agree, and paths match on whole-segment boundaries. Redirects are checked
at every hop.

`github: true` appends the GitHub API, raw, codeload, objects, and release-asset
hosts. Real Git is sensitive by default because aliases, helpers, hooks,
submodules, and repository configuration can create work outside the
in-process middleware. If Git is explicitly allow-listed, `git-hosts` applies
defense-in-depth checks to recognized remotes, but it is not an OS-level egress
boundary. URL prefixes do not grant Git access.

`methods`, `max-response`, `max-request`, and `timeout` replace the downloader
defaults. Request and response sizes accept bytes or units such as `KiB`,
`MiB`, `GB`, and `GiB`. Curl data flags are sent under the request cap; `@file`
inputs must resolve inside the run root.
`headers` injects values into every in-process request, which can keep a broker
token out of the installer source.

`dns-server` selects an IP address and optional port for HTTP hostname lookups.
It defaults to Quad9's malware-blocking, DNSSEC-validating resolver at
`9.9.9.9:53`. Set `dns-server: ""` to use the host's system resolver, or replace
it with another resolver such as `1.1.1.2:53`. The setting applies to the
initial remote script fetch and to in-process `curl`/`wget`; it does not control
DNS performed by explicitly allowed host binaries or by an HTTP proxy. Queries
to this resolver use ordinary unencrypted DNS.

An explicitly empty `urls: []` means deny every fetch. A key with no value,
such as an unfinished `urls:`, is null and leaves the defaults unchanged.

## Emulation

Emulation allows a platform-specific installer to be exercised on another
host. `uname-os` and `uname-arch` replace selected `uname` answers. Files such
as `/etc/os-release` are presented virtually to shell tests, reads, and
`source` operations; they are not written to the host filesystem.

This is behavior emulation, not a VM or container. External binaries still run
for the real host architecture and operating system.

## Mocks

Mocks are evaluated in order before the network layer and command allow-list.
They operate on the real command after wrapper resolution and return configured
stdout, stderr, and an exit code without launching the command.

A `match` block supports:

| Matcher | Meaning |
|---|---|
| `args` | Exact argument vector |
| `prefix` | Argument-vector prefix |
| `name` | One of the listed command names |
| `glob` | Glob over the normalized complete command line |
| `resource` | Resource kind and globbed value, such as a URL or path |

Criteria in the same block are combined with AND. Dynamic predicates and
computed mock responses are available only through the [Go API](go-api.md).

## Flags and paths

A flag only overrides its corresponding policy value when the user explicitly
types it. Naming a script on the command line replaces both `script` and `args`,
preventing arguments intended for one installer from leaking into another.

Relative paths are resolved against the process's working directory.

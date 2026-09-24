# smash — a policy-controlled shell for install scripts

`smash` runs `curl | bash`-style installers through a shell interpreter under a
policy you control. It records what each command touched and lets you restrict
commands and downloads, mock responses, and inspect the resulting file-change
story without modifying the installer.

> [!IMPORTANT]
> `smash` is an **in-process policy and auditing layer**, not an OS sandbox or
> container. External commands are real host binaries, and an unmodelled command
> runs with an audit warning unless `-strict` is enabled. Use `-strict` for
> scripts you do not trust, and add OS-level confinement when you need a hard
> security boundary.

| Capability | What `smash` does |
|---|---|
| Shell | Interprets scripts with [`mvdan.cc/sh/v3`](https://github.com/mvdan/sh) |
| Commands | Blocks sensitive commands, audits ordinary unlisted commands, and supports strict allow-listing |
| Downloads | Handles `curl` and `wget` in-process under a structural URL allow-list |
| Other network tools | Models 60-plus command families and denies off-policy egress |
| Visibility | Logs resources, typed parameters, file changes, exit status, and optional stdin/stdout |
| Control | Disables commands or mocks their stdout, stderr, and exit status |

The test suite exercises real installers including uv, RVM, Docker's
`get-docker`, Fly.io, Homebrew, nvm, Starship, Terragrunt, and several
GoDownloader-based installers. See [the test catalogue](docs/tests.md).

## Quick start

A fresh clone generates a patched copy of `mvdan/sh` before building:

```bash
git clone https://github.com/rezen/smash
cd smash
just install
```

Run a local installer and write its audit trail to a file:

```bash
smash \
  -urls https://api.fly.io/,https://github.com/superfly/,https://release-assets.githubusercontent.com \
  -audit fly-audit.yaml \
  fixtures/fly.sh --non-interactive
```

When stdin, stdout, and stderr are attached to a capable terminal and the audit
target is the default `-`, Smash opens a `tview` split view. A PTY-backed
terminal in the upper pane preserves TTY detection, ANSI output, and
interactive prompts—including programs and shell redirections that open
`/dev/tty` directly—while audit events stream through the scrollable lower
pane. Press `F6` to switch panes and `Ctrl-C` to stop; after the run, press
Enter, Escape, or `q` to close the view. Piped or redirected runs keep their
ordinary stdout/stderr behavior.

Profile a script into a reusable manifest, review it, then enforce that exact
profile on later runs:

```bash
smash -profile -profile-output install.manifest.yaml fixtures/fly.sh --non-interactive
$EDITOR install.manifest.yaml
smash -manifest install.manifest.yaml fixtures/fly.sh --non-interactive
```

The manifest records the profiling OS, binds the run to the script body's
SHA-256, and contains sorted, de-duplicated `commands`, `urls`, `hosts`, and
`mime-types` lists — GitHub downloads are scoped in `urls` to the owner/repo
actually observed (`https://github.com/example/tool`) rather than the whole
forge, hosts include redirect targets (GitHub's opaque uuid/hash asset hosts
stay host-level), and the media types are the ones the responses actually
declared, because profiling runs `curl` and `wget` through the same
in-process downloader an enforced run uses (in an observe-only configuration
that admits everything). The run's full audit trail lands beside the manifest
as `<name>.manifest.log`, so the evidence for each grant travels with it. A
manifest run fails before execution if the OS or script changed, enables strict
command gating, and replaces the run's command and network grants with those
lists. Profile mode is otherwise
deliberately unrestricted: Smash audits but does not enforce command, disabled,
mock, egress, sleep, or raw-socket policy layers. Run profiling
only for a trusted script or inside an OS sandbox/container. Command statuses
remain unchanged for conditions and `&&`/`||` lists, while profile mode ignores
the shell's `set -e` termination action so it does not truncate discovery. It
never turns a wrapped `sudo` into real privilege escalation.

Or give `smash` the URL that would normally be piped to a shell:

```bash
smash \
  -urls https://releases.astral.sh/,https://release-assets.githubusercontent.com/ \
  https://astral.sh/uv/install.sh
```

The script URL is fetched up front, like `curl -fsS`. Downloads made *by the
script* go through the policy. Each run recreates `./sandbox`, with `HOME`,
`TMPDIR`, and the first `PATH` entry pointing inside it.

An audit record describes behavior in terms of resources rather than only the
raw command line:

```yaml
- name: curl
  resources:
    - fetch url https://example.com/tool.tar.gz
    - write path $TMPDIR/tool.tar.gz
  command: curl -fsSL https://example.com/tool.tar.gz -o $TMPDIR/tool.tar.gz
  exit: 0
  content-type: application/gzip
- name: tar
  resources:
    - read archive $TMPDIR/tool.tar.gz
    - chdir path ~/.local/bin
  command: tar -C ~/.local/bin -xf $TMPDIR/tool.tar.gz
  exit: 0
```

Useful command-line controls:

| Flag | Purpose |
|---|---|
| `-policy FILE` | Read the complete run configuration from YAML |
| `-profile` | Run and write a manifest with the script hash, commands, GitHub owner/repo URL prefixes, and hosts |
| `-profile-output FILE` | Choose the profile path instead of `<script>.manifest.yaml` |
| `-manifest FILE` | Verify the script hash and enforce a reviewed profile |
| `-urls PREFIXES` | Replace the URL prefixes available to `curl` and `wget` |
| `-git-hosts HOSTS` | Apply advisory host checks when real Git is explicitly allowed |
| `-dns-server IP[:PORT]` | Override the malware-blocking DNS resolver; empty uses system DNS |
| `-allow COMMANDS` | Add commands to the allow-list, including deliberate grants for sensitive commands |
| `-disable COMMANDS` | Deny commands after wrappers such as `sudo`, `env`, and `sh -c` are resolved |
| `-strict` | Block every command that is not allow-listed |
| `-allow-in-root` | Explicitly permit native executables installed below the run root |
| `-audit FILE\|-` | Write the YAML audit stream to a file or stderr |
| `-data N` | Capture up to `N` bytes of stdin and stdout per command |

See the [CLI reference](docs/cli.md) for every flag and its precedence rules.

## Policy files

Flags work well for a short run. For reviewable and repeatable configuration,
generate a policy file:

```bash
smash -init-policy policy.yaml
# edit policy.yaml
smash -policy policy.yaml
```

A small policy can define the script, its network access, command controls, and
audit output together:

```yaml
script: fixtures/fly.sh
args: [--non-interactive]
root: sandbox

audit:
  path: fly-audit.yaml
  data: 200

commands:
  disable: [rm, rmdir]

network:
  urls:
    - https://api.fly.io/
    - https://github.com/superfly/
    - https://release-assets.githubusercontent.com
  git-hosts: [github.com]
  max-request: 8MiB

strict: false
allow-in-root: false
timeout: 2m
```

Policies can also inject request headers, emulate a target OS, add environment
variables, restrict request methods and request/response sizes, and mock commands by
argv, prefix, name, glob, or resource. Unknown YAML keys are rejected. See the
[policy reference](docs/policy.md).

## What is enforced

The interpreter runs shell syntax itself, but delegates external commands such
as `tar`, `sed`, and `uname` to real host binaries. Before execution, the
middleware stack:

1. unwraps commands hidden behind `sudo`, `env`, `timeout`, `xargs`,
   `find -exec`, and similar wrappers;
2. reinterprets `sh -c` and shell scripts found inside the run root;
3. applies mocks, command policy, URL policy, and the general egress guard;
4. records the command's resources, file changes, data, and result.

`curl` and `wget` are executed by an in-process HTTP client. URL rules match the
scheme and host exactly and the path on segment boundaries, and every redirect
is checked again. Other modelled clients—including Git, SSH, OpenSSL, package
managers, and container CLIs—are checked by their parsed egress intent.

The boundary remains soft: environment paths point inside the run root, but a
permitted host binary can write elsewhere, and an unmodelled network client is
not recognized unless strict mode blocks it. Native executables below the root
are blocked unless `-allow-in-root` explicitly grants that unsafe capability;
real Git is likewise sensitive by default because its helpers and repository
configuration can spawn work outside the in-process model. The [security
model](docs/security-model.md) explains the guarantees, escape-hatch handling,
and options for OS-level confinement.

## Documentation

- [CLI reference](docs/cli.md) — flags, script loading, precedence, and a worked run
- [Policy reference](docs/policy.md) — every YAML section, matching, and examples
- [Security model](docs/security-model.md) — guarantees, limitations, network checks, and hardening
- [Architecture](docs/architecture.md) — command capabilities, parsing, wrappers, auditing, and emulation
- [Go API](docs/go-api.md) — configuring and embedding the runner
- [Test catalogue](docs/tests.md) — installer coverage and the behavior each test pins
- [Repository layout](docs/layout.md) — package and fixture map

## Development

```bash
just test                     # unit and integration tests
just test -run TestNoclobber  # pass arguments through to go test
just race                     # race detector
just ci                       # formatting, tidy, vet, build, test, race, and cross-build
```

The generated `third_party/sh` tree is intentionally untracked. Run `just sync`
if it is missing; recipes that need it do this automatically.

# Architecture

`smash` separates shell interpretation, command understanding, policy
enforcement, and user-facing configuration into a CLI and three internal
packages:

```text
cmd/smash          CLI, script loading, root setup, flag precedence, PTY-backed tview UI
internal/policy    YAML schema, validation, and template generation
internal/command   pure argv parsing and command capabilities
internal/sandbox   mvdan/sh runner, enforcement middleware, and auditing
```

The [repository layout](layout.md) lists the individual files and fixtures.

## Execution path

For each external command, the runner follows this conceptual path:

```text
shell AST
  → unwrap wrappers
  → identify and parse command family
  → apply disable rules and mocks
  → reinterpret shell runners when needed
  → apply downloader, egress, and command gates
  → execute in-process behavior or a host binary (attached to the script PTY when interactive)
  → record resources, file changes, streams, and result
```

The concrete middleware ordering preserves two important properties: all guards
see the real command behind wrappers, and an explicitly disabled command cannot
be mocked back into existence.

## Command capabilities

Command handling is a small type system. Every family implements `Command`,
while optional interfaces advertise behavior needed by guards and auditors.

| Interface | Method | Purpose |
|---|---|---|
| `Command` | `Names`, `Parse` | Register names and turn argv into a `ParsedCommand` |
| `Networked` | `Egress` | Describe whether and where an invocation accesses the network |
| `Downloader` | `Request` | Supply an HTTP request for in-process `curl` or `wget` |
| `Wrapper` | `Unwrap` | Expose commands hidden behind `sudo`, `env`, `xargs`, `find`, and similar tools |
| `ScriptRunner` | `DashC` | Expose a shell string for confined reinterpretation |
| `Structured` | `Params` | Return a command-specific typed parameter struct |
| `Describer` | `Resources` | Describe resources requiring command-specific logic |
| `PathMutator` | `Targets` | Report paths a permission-style command changes |
| `FileOperator` | `FileChanges` | Report semantic filesystem changes |
| `Builtin` | `builtin` | Mark known local tools used to derive the default allow-list |

Guards discover these interfaces by type assertion. Adding a new downloader,
wrapper, or network family generally changes the registry rather than the
guards themselves.

## Registry and parser

Each command family declares a `Spec` describing value-taking flags, clustered
short options, and subcommand behavior. The generic parser returns a
`ParsedCommand` containing normalized flags, operands, and an optional
subcommand. Order-sensitive commands such as `find` use specialized parsing.

The registry refuses duplicate names at construction. This prevents a benign
builtin definition from shadowing a networked or wrapper-aware definition.

Different command families remain separate when their superficially similar
syntax has different meaning. Examples include:

- `curl -o` selects an output file, while `wget -o` selects a log file and
  `wget -O` selects output;
- SSH uses `-p` for a port, while SCP uses it to preserve timestamps;
- rsync remote locations are operands rather than a dedicated destination
  flag;
- `xargs -i` accepts an attached optional replacement string and defaults to
  `echo` when no command is present;
- `find` interleaves predicates and command actions, so it cannot be parsed as
  an ordinary prefix wrapper.

## Typed, reversible parameters

Commands implementing `Structured` expose structs such as `CurlParams`,
`SSHParams`, and `DockerRunParams`. Struct tags declare flags, operands,
secrets, and resource semantics once. The binder derives parsing and rendering
behavior from those tags, reducing drift between the accepted command line and
the typed form. Anonymous embedded structs flatten, so a family of subcommands
can share common fields (docker's `DockerGlobals`).

Every `ParsedCommand` can render a normalized command line with `String()`.
Where typed parameters exist, applications can inspect or edit the struct and
render it back to argv.

`find` remains hand-written because its expression order is significant.

## Notable command families

### Container CLIs

`DockerCommand` models `docker`, `podman`, and `nerdctl`. The grammar puts
global daemon options before the subcommand, so parsing splits the argv there;
that keeps overloaded short options unambiguous by position (`-c` is
`--context` globally but `--cpu-shares` after `run`). Subcommand families with
flags worth reading by name have their own params structs — `DockerRunParams`
(mounts, published ports, capabilities, the command inside the container),
`DockerBuildParams`, `DockerLoginParams`, `DockerExecParams` — each embedding
`DockerGlobals`; the rest share the generic `DockerParams`. Registry-capable
operations such as `pull`, `push`, `build`, and `run` implement `Networked` and
remain subject to the egress guard.

### Package managers

One data-driven `PackageManager` type covers host and language ecosystems such
as apt, yum/dnf, zypper, apk, pacman, brew, nix, pip/uv, npm/yarn, gem, Cargo,
Go, Composer, and CPAN. Each entry identifies networked subcommands or flags;
an explicit URL operand always counts as egress. Offline inspection and local
package installation can therefore remain distinct from repository access.

### Long-tail network tools

`NetTool` describes utilities such as dig, whois, ping, telnet, aria2c, SVN,
Mercurial, MySQL, and PostgreSQL clients. Entries can define networked
subcommands, host flags, positional host/port pairs, and whether egress is
unconditional.

### Interpreters

Python and Perl network behavior is recognized heuristically for selected
`-m`, `-M`, and `-c` forms. The parser looks for network modules, explicit URLs,
and common socket endpoints. Opaque script files remain governed primarily by
the sensitive-command gate.

### OpenSSL and GPG

OpenSSL is modelled by operation: `s_client` is networked, `dgst` is an offline
digest/signing operation, and encryption/decryption modes describe their input,
output, key, and direction. Passphrase-bearing options are secret fields.

GPG is a permitted local tool for verification but also implements `Networked`.
Keyserver, receive, search, send, fetch, refresh, locate, and automatic retrieval
operations are identified as egress even when offline GPG work is allowed.

## Wrappers and nested shells

`unwrapMiddleware` repeatedly peels types implementing `Wrapper`, preserving
their names for the audit record. It understands each wrapper's value-consuming
options and positional syntax before returning the inner argv.

A shell command with `-c` is not passed to a host shell. `shInterpMiddleware`
parses the string and builds a nested runner from the same configuration, so
every inner command is enforced. Shell scripts installed inside the root take
the same path. Recursion is depth-capped, and execution shares the run's context
timeout.

## Egress model

Every `Networked` command produces an egress description from its parsed argv.
A single guard consumes that description rather than embedding network policy
in every middleware branch. This keeps offline and online forms of a tool
distinct.

Each egress target is classified before the guard judges it: a **URL** is
matched against the URL prefix allow-list, an **endpoint** (host, host:port,
user@host) against the allowed-hosts list, and an **indicator** — a target
that names the networked operation rather than a place, such as `apt-get`'s
`install`, `gpg --recv-keys`, or a Python module — is off-policy by
definition, since no allow-list entry can name one. Most targets classify by
shape; commands whose labels read like bare hostnames (`socket`, `install`,
`s_client`) classify themselves.

Git is sensitive by default because a real Git process can launch aliases,
helpers, hooks and transports outside the middleware. When explicitly granted,
named remotes are resolved from `.git/config`, dangerous command-line rewrites
and submodule operations fail closed, and `Policy.GitHosts` supplies advisory
checks separate from downloader URL prefixes. `/dev/tcp` and `/dev/udp` are
detected in the interpreter's file-open path because they never become external
commands.

`curl` and `wget` additionally implement `Downloader`. Their request objects are
executed by `internal/tool` in both modes — under the policy-configured HTTP
client when enforcing, and under an observe-only configuration in profile
mode — rechecking redirects, bounding request and response bodies, and
confining runner-controlled input and output files. Every response with a
body is observed: its declared `Content-Type` and the detected type of its
first bytes (`http.DetectContentType` sharpened by a magic-number table, so
an octet-stream download reads as the tar/xz/executable/script it is) appear
in the audit record as `content-type` and `sniffed`, and a redirect chain
that crossed hosts appears as `via`. When the policy sets a
`mime-types` allow-list, the declared and sniffed types are additionally
checked before the body is delivered.

See the [security model](security-model.md) for the guarantees and limits of
these mechanisms.

## Resources and file changes

`ParsedCommand.Describe()` returns actions over typed resources—for example:

```text
curl: fetch url https://example.com/x, write path out.tgz
chmod: apply mode 755, modify path bin/tool
```

Most structured fields declare their resource kind and action through tags.
Commands whose semantics depend on several arguments implement `Describer`.
Examples include tar direction, find command actions, install sources and
destinations, and local-versus-remote rsync operands.

Filesystem monitoring uses `FileChange{Op, Path, From, Recursive}`. It can
distinguish deletion, movement, copying, linking, extraction, writes, and mode
changes. Data-driven `FileTool` and `TransferTool` definitions cover common
utilities; specialized implementations handle tar, sed, rsync, compression,
and similar commands.

Redirections, `source`, and extra file descriptors are handled by the shell
interpreter rather than an external command. An auditor implementing
`OpenAuditor` receives those reads, writes, and appends separately.

## Auditing

An `AuditRecord` contains the normalized command, typed parameters, resources,
file changes, wrapper chain, exit status, duration, and any execution or policy
error. `unlisted` and `in-root` identify how a command passed the gate.

With `AuditData` enabled, middleware tees bounded stdin and stdout samples into
the record. `TextAuditor` writes a YAML sequence that tools such as `yq` can
query. `ShortPaths` renders locations below the run root as `~/…`, `$TMPDIR/…`,
or `$ROOT/…` while retaining full paths in memory.

Secrets are removed from both command lines and typed parameters according to
field tags, shared well-known flags, and command-specific secret flags.

Applications can implement `Auditor` to emit JSON, store records in a database,
or stream them elsewhere.

## Target-OS emulation

The optional `Emulation` configuration can provide selected `uname` values and
virtual files such as `/etc/os-release`. Stat, access, and open handlers make
those files visible to shell tests and `source` without placing them on the
host.

This is enough to exercise detection branches in Linux-only installers such as
Docker's `get-docker` while retaining the same command policy. It does not
emulate a CPU or kernel and cannot make incompatible native executables run.

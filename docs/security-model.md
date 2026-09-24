# Security model

`smash` is a language-level enforcement and observability layer for install
scripts. It is designed to make script behavior explicit and controllable while
still allowing real installer flows to complete. It is not a process, kernel,
filesystem, or network namespace.

## Boundary at a glance

| Area | Enforced by `smash` | Important limitation |
|---|---|---|
| Shell language | Parsed and interpreted in-process | Compatibility follows the patched `mvdan/sh` interpreter, not a host Bash process |
| Commands | Sensitive and disabled commands are blocked; strict mode requires allow-listing | Allowed commands are real host binaries; trusted paths are snapshotted before the script changes `PATH` |
| `curl` and `wget` | In-process HTTP client with URL, method, redirect, timeout, and size policy | The URL initially supplied as `SCRIPT` is fetched before the run |
| Other network commands | Parsed egress intent is checked for modelled command families | An unmodelled client can run in non-strict mode |
| Filesystem | Runner-controlled download outputs are confined; in-process `mktemp` honors `TMPDIR`; `HOME` and `TMPDIR` point into the root | A permitted host binary can write outside it |
| Visibility | Commands, shell opens, resources, file changes, and optional data are audited | Descriptions reflect the command model, not kernel-level system-call tracing |

For an untrusted script, enable `-strict` and allow only the commands needed by
that installer. Add OS-level confinement when host-level isolation matters.

## Shell execution

`mvdan/sh` interprets the shell language. External commands such as `uname`,
`tar`, and `sed` are delegated to host executables through `os/exec` after the
policy stack has inspected them. `base64`, `mktemp`, `sha256sum`, `curl`, and
`wget` have implementations under `internal/tool` that run in-process.

The runner sets `HOME`, `TMPDIR`, and the leading `PATH` entry inside the run
root. Its `mktemp` implementation reliably uses that `TMPDIR` when a template
does not name a directory, independent of host GNU/BSD behavior. It also
exposes Bash/POSIX compatibility variables needed by common installers. These
settings guide well-behaved tools into the root but do not prevent a host
executable from naming and modifying another absolute path.

## Command policy

The default command gate has three outcomes:

1. Known local installer tools run normally.
2. Ordinary unlisted commands run with a diagnostic and `unlisted: true` in
   their audit record.
3. Sensitive commands are blocked with exit status 127 unless deliberately
   added to the allow-list.

The sensitive list includes privilege tools, shells running opaque files,
general-purpose interpreters, host package managers, service managers, and
other commands that can escape the policy or affect the host broadly.

Strict mode changes the second outcome: every command not allow-listed is
blocked. This closes the residual gap where a network-capable or filesystem-
mutating executable unknown to the command registry would otherwise run.

The explicit disable list wins over mocks and allow-list entries.

## Programs installed inside the root

Resolving below the run root is not permission to execute opaque native code.
Native executables are blocked by default, including in strict mode, and can be
enabled only with the explicit `allow-in-root` capability. When enabled they
are marked `in-root: true` in the audit record and run outside the command and
network model.

Interpreted files remain governed by the executable that will interpret them:

- a script with `#!/usr/bin/env python3` is treated as `python3`, which is
  sensitive until allowed;
- a shell script is parsed and run by a confined sub-runner;
- commands executed by that shell script pass through the same middleware
  stack again.

The command gate checks the resolved in-root location before applying a basename
allow-list entry, and allowed host commands are resolved against a PATH snapshot
taken before script execution. A payload cannot therefore inherit an allow-list
grant merely by naming itself `uname` or shadowing that name in `PATH`.

## Shell strings and wrappers

Allowing a host shell to execute an opaque `-c` string would bypass every inner
check. When the command model recognizes `sh -c`, `bash -c`, or an equivalent
shell runner, `smash` parses the string and executes it through a nested runner
with the same policy. Nesting is depth-limited and covered by the run timeout.

The policy also resolves wrappers before enforcement. This includes:

- `sudo` and `doas`;
- `env`, `command`, `time`, `nice`, `nohup`, `setsid`, and `stdbuf`;
- `timeout` and `watch`;
- `xargs`;
- `find -exec`, `-execdir`, `-ok`, and `-okdir`.

Consequently, `env curl`, `timeout 5 openssl s_client`, `sudo rm`, and `find
-exec sh -c …` are judged by their inner command. The wrapper chain remains in
the audit record.

`sudo CMD` and `doas CMD` are de-escalated: only `CMD` runs, without privilege
escalation. With `allow-sudo` enabled, credential probes such as `sudo -v` and
`sudo -n -l CMD` report success so an installer can proceed past its capability
check; subsequent commands still do not gain privileges.

## Download policy

`curl` and `wget` are not launched as host binaries. Their parsed request is
executed by a configurable Go `http.Client`, allowing `smash` to enforce:

- structural URL-prefix matching;
- an HTTP method allow-list;
- a request-body limit and root-confined `@file` inputs;
- a response-body limit;
- an optional response MIME-type allow-list, checked against both the declared
  `Content-Type` and a 512-byte content sniff of the body;
- per-request timeouts;
- injected headers;
- proxy and TLS behavior supplied by the configured transport;
- a configurable DNS resolver, defaulting to Quad9's malware-blocking service;
- the same policy on every redirect hop.

URL prefixes are not raw string prefixes. The scheme and hostname match
exactly, explicit non-default ports must agree, and the configured path matches
only on a segment boundary. For example, `https://example.com/pkg` admits
`/pkg/v1`, but not `/pkgs` or a host such as `example.com.evil.test`.

URLs containing user information or raw/encoded `.` and `..` path segments are
rejected before allow-list matching. These shapes can otherwise appear to name
one location while resolving or normalizing to another.

The shell builtin `command -v curl` or `command -v wget` is intercepted so an
installer can select a downloader even when the corresponding host executable
does not exist.

The output path of in-process `curl -o` or `wget -O` must remain inside the run
root. This is a real filesystem guarantee because `smash` itself performs that
write.

When a policy sets `network.mime-types`, a response body is delivered only if
its declared `Content-Type` matches the list and its first bytes do not sniff
as a disallowed type — which catches an HTML error or portal page served under
an archive's name. The sniff is `http.DetectContentType` sharpened by a
magic-number table (tar, xz, zstd, bzip2, 7z, deb/rpm/xar packages, ELF,
Mach-O and PE executables, and shebanged scripts by interpreter), so the
audit names what an `application/octet-stream` download actually was. The
refinement is observability, not policy: a detected binary type passes the
gate wherever plain octet-stream did, so this still gates labels, not
content — checksum verification remains the integrity check. HEAD requests
and empty bodies deliver no content and are exempt. The declared and sniffed
types are recorded in the audit trail either way.

The DNS default adds a reputation-based block before connection, but it is not
a hard security boundary: ordinary DNS is unencrypted, an HTTP proxy may
resolve destinations itself, and explicitly allowed host binaries use their
own resolver behavior. `-dns-server ""` selects the system resolver; a policy's
`network.dns-server` can name another IP and optional port.

## General egress guard

Downloaders are not the only network clients. A command-family registry parses
network intent for Git, SSH, SCP/SFTP, rsync, OpenSSL, netcat, GPG, container
CLIs, package managers, database clients, language interpreters, and other
network utilities.

Each parsed invocation answers whether it reaches a network destination and,
when possible, which destination. A shared egress guard then applies the
appropriate policy. Offline operations remain usable—for example, `openssl
dgst` does not egress while `openssl s_client -connect …` does.

Real Git is sensitive by default. The exact `git --version` probe is allowed so
installers can detect it, but every functional Git invocation requires an
explicit grant. This is necessary because Git aliases, hooks, helpers,
submodules, command-line configuration, and repository configuration can spawn
processes the in-process middleware cannot observe.

For an explicitly granted Git process, `git-hosts` remains defense in depth:
recognized remotes are checked, named remotes are resolved through
`.git/config`, submodule operations fail closed, and command-line settings that
rewrite URLs or select helpers are rejected. It is not a hard egress guarantee;
use OS-level network confinement when running real Git against untrusted state.

Interpreter `-c` and `-m` forms are inspected heuristically for network modules,
URLs, and common socket patterns. A script file passed to Python, Perl, Ruby,
Node, or another general-purpose interpreter is opaque; that is why these
interpreters are sensitive commands by default.

## Raw shell sockets

Bash-style `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` access appears to the
interpreter as a file open. An open-handler detects, audits, and denies these
paths before a socket is created.

This does not turn the process into a network namespace. A permitted, unmodelled
native binary can still open a socket, including when `allow-in-root` is set.

## Filesystem visibility

The command model reports operations such as delete, move, copy, link, extract,
write, and mode changes. Shell-controlled opens—including redirections and
`source`—are audited separately because they never enter the external-command
middleware.

This visibility is semantic rather than kernel-enforced. `HOME`, `TMPDIR`, and
tool-specific install variables direct conventional installers into the root,
and downloader outputs are checked, but a permitted host program can ignore
those conventions. A future path-scope guard can consume the command model's
`PathMutator` targets, but it still would not replace system-call confinement.

## Audit data and secrets

Audit records can include the normalized command line, typed parameters,
resources, wrappers, file changes, exit status, timing, errors, policy-denial
reasons, and bounded stdin/stdout samples.

Fields and flags known to contain credentials—headers, cookies, passwords,
keys, and command-specific secret options—are redacted before logging. This is
best-effort structural redaction; arbitrary secrets printed by a command can
still appear when data capture is enabled. Choose the `audit.data` setting and
log destination accordingly.

## Profile manifests

A profile manifest associates an observed command and network surface with
the profiling OS and binds it to the SHA-256 of the script bytes. Enforcing
it rejects a different OS or changed script and turns the observed commands,
owner/repo GitHub URL prefixes, and exact hosts into strict grants. The
`urls` list scopes project-shaped GitHub-family downloads to the owner/repo
that was actually observed — including redirect hops — instead of granting
the whole forge; those prefixes also pin the scheme, unlike host grants.
GitHub's opaque uuid/hash asset hosts carry no project identity in their
paths and stay host-level in `hosts`, as does everything non-GitHub. A
`mime-types` list additionally applies the response MIME
gate described under the download policy; the profiler records the declared
types it observed (and omits the list whenever a download body arrived without
a parseable `Content-Type`, since enforcement would then deny the profiled
script itself). The hash does not establish who
authored the script, and a profile is not a static proof of all possible
behavior: different arguments, environment, platform, network responses, or
timing may select branches that were not exercised.

Profiling is intentionally non-enforcing so discovery is not truncated by a
Smash policy decision. Command denials, strict mode, mocks, downloader
allow-lists, egress controls, the sleep cap, in-root native executable checks,
and the raw-socket guard are bypassed while audit collection remains active.
`curl` and `wget` still run through the shared in-process downloader — in an
observe-only configuration that admits every URL, method, and media type,
pins the transport to the default resolver and caps, and keeps output
confined to the root — so discovery exercises the implementation a manifest
is later enforced against, and redirect hops and response media types are
recorded. Every other network-capable command runs as a real host process. Profile only trusted
scripts or add an OS-level sandbox/container, review manifests before
enforcement, and profile every execution variant that matters. Non-zero exits
remain visible to the audit, conditionals, and AND/OR lists, but the interpreter
ignores the `set -e` termination action so errexit cannot truncate discovery.
`sudo` wrappers remain unwrapped and never grant real privilege.

## Hardening beyond in-process enforcement

For a hard boundary, run `smash` within a mechanism that constrains its child
processes at the OS or virtualization layer:

- on macOS, use an appropriate Seatbelt profile where available;
- on Linux, use user namespaces plus seccomp and filesystem controls such as
  Landlock or bubblewrap;
- on either platform, use a container, sandbox service, or microVM.

These layers complement `smash`: the OS boundary limits consequences, while
the command and resource model provides installer-specific policy, mocks, and
an intelligible audit trail.

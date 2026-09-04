# Security model

`smash` is a language-level enforcement and observability layer for install
scripts. It is designed to make script behavior explicit and controllable while
still allowing real installer flows to complete. It is not a process, kernel,
filesystem, or network namespace.

## Boundary at a glance

| Area | Enforced by `smash` | Important limitation |
|---|---|---|
| Shell language | Parsed and interpreted in-process | Compatibility follows the patched `mvdan/sh` interpreter, not a host Bash process |
| Commands | Sensitive and disabled commands are blocked; strict mode requires allow-listing | Allowed commands are real host binaries |
| `curl` and `wget` | In-process HTTP client with URL, method, redirect, timeout, and size policy | The URL initially supplied as `SCRIPT` is fetched before the run |
| Other network commands | Parsed egress intent is checked for modelled command families | An unmodelled client can run in non-strict mode |
| Filesystem | Runner-controlled download outputs are confined; `HOME` and `TMPDIR` point into the root | A permitted host binary can write outside it |
| Visibility | Commands, shell opens, resources, file changes, and optional data are audited | Descriptions reflect the command model, not kernel-level system-call tracing |

For an untrusted script, enable `-strict` and allow only the commands needed by
that installer. Add OS-level confinement when host-level isolation matters.

## Shell execution

`mvdan/sh` interprets the shell language. External commands such as `uname`,
`tar`, and `sed` are delegated to host executables through `os/exec` after the
policy stack has inspected them.

The runner sets `HOME`, `TMPDIR`, and the leading `PATH` entry inside the run
root. It also exposes Bash/POSIX compatibility variables needed by common
installers. These settings guide well-behaved tools into the root but do not
prevent a host executable from naming and modifying another absolute path.

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

An installer must usually execute the binary it just installed. A program that
resolves inside the run root can therefore execute and is marked `in-root: true`
in the audit record.

This is not an unrestricted escape hatch. Policy is based on the executable
that will actually interpret the file:

- a script with `#!/usr/bin/env python3` is treated as `python3`, which is
  sensitive until allowed;
- a shell script is parsed and run by a confined sub-runner;
- commands executed by that shell script pass through the same middleware
  stack again.

A newly installed opaque native binary remains a real process. Known package
manager and network subcommands are inspected by argv, but this is not a
substitute for OS isolation.

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
- a response-body limit;
- per-request timeouts;
- injected headers;
- proxy and TLS behavior supplied by the configured transport;
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

## General egress guard

Downloaders are not the only network clients. A command-family registry parses
network intent for Git, SSH, SCP/SFTP, rsync, OpenSSL, netcat, GPG, container
CLIs, package managers, database clients, language interpreters, and other
network utilities.

Each parsed invocation answers whether it reaches a network destination and,
when possible, which destination. A shared egress guard then applies the
appropriate policy. Offline operations remain usable—for example, `openssl
dgst` does not egress while `openssl s_client -connect …` does.

Git uses `git-hosts`, independently of downloader URL prefixes. Named remotes
are resolved through `.git/config` before checking the host. This prevents an
apparently harmless `git fetch origin` from hiding an off-policy remote.

Interpreter `-c` and `-m` forms are inspected heuristically for network modules,
URLs, and common socket patterns. A script file passed to Python, Perl, Ruby,
Node, or another general-purpose interpreter is opaque; that is why these
interpreters are sensitive commands by default.

## Raw shell sockets

Bash-style `/dev/tcp/HOST/PORT` and `/dev/udp/HOST/PORT` access appears to the
interpreter as a file open. An open-handler detects, audits, and denies these
paths before a socket is created.

This does not turn the process into a network namespace. A permitted, unmodelled
native binary can still open a socket in non-strict mode.

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

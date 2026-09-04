# smash — a sandboxed bash for install scripts

`smash` runs `curl | bash`-style install scripts inside a policy you control,
and tells you what they did. It is a real POSIX shell interpreter
([`mvdan.cc/sh/v3`](https://github.com/mvdan/sh), in Go) wrapped in an
enforcement stack: a command gate (sensitive commands blocked, the boring
rest audited), an in-process HTTP client for `curl`/`wget` under a URL
allow-list, a scoped filesystem root, and an audit trail that describes every
command by the resources it touched. You
can **monitor** a script (see every fetch, write, delete, chmod, with typed
params and optional stdin/stdout capture) and **alter** it (deny commands,
restrict URLs, mock any command's output or exit code) without editing the
script.

It has been exercised against real installers — `uv`, `rvm`, Docker's
`get-docker`, Fly.io's `fly.sh` — vendored under [`fixtures/`](fixtures), so you
can see exactly where the model holds and where it stops.

| | `smash` |
|---|---|
| What it is | Real POSIX shell **interpreter**; scripts run unmodified |
| External commands | Delegated to **real** host binaries via `os/exec`; sensitive ones (sudo, shells, interpreters, host package managers, …) blocked, the rest audited — or `-strict` for allow-list only |
| Filesystem | Real FS. `HOME`, `TMPDIR` and `PATH` point inside a scoped directory, and the one write `smash` performs itself (`curl -o`) is confined to it; a host binary's own writes are not — see [the soft boundary](#what-the-sandbox-does) |
| Network | `curl`/`wget` served **in-process** via `net/http` under a URL allow-list; every **modelled** network command (60-plus families: ssh, nc, git, openssl, the package managers, the net tools) denied by an egress guard. An unmodelled one runs unless `-strict` |
| Visibility | Every executed command described by resource (`fetch url …`, `delete path …`), with typed params, file changes, and optional stdin/stdout capture |
| Control | Disable commands outright; mock any command's stdout/stderr/exit by matcher |
| Track record | uv, rvm, get-docker and fly.sh installers run to completion under policy; the binaries they install execute afterwards |

It is **in-process only** — no OS confinement, no container. That was the
chosen isolation level. See [Hardening](#hardening-beyond-in-process) to go further.

## Run it

Give `smash` an installer — a local path or an `http(s)://` URL — and a policy.
It runs the script in a fresh `./sandbox` root with `HOME` and `TMPDIR` inside,
and writes an audit log of what happened. When the sandbox itself refuses a
command, the log line carries the reason (`reason: curl: [sandbox] URL not in
allow-list: …`) even if the script threw curl's stderr away:

```bash
git clone https://github.com/rezen/smash && cd smash
just install                  # generates third_party/sh, then `go install ./cmd/smash`
                              # (`go install …@latest` cannot work: go.mod replaces
                              #  mvdan.cc/sh with the generated, untracked third_party/sh)

smash \
  -urls https://api.fly.io/,https://github.com/superfly/,https://release-assets.githubusercontent.com \
  -audit fly-audit.log -data 200 \
  fixtures/fly.sh --non-interactive

# the curl | bash idiom, minus the pipe: the URL is fetched like `curl -fsS`,
# then run under the policy. Only the script's own downloads hit the allow-list.
smash -urls https://releases.astral.sh/,https://release-assets.githubusercontent.com/ \
  https://astral.sh/uv/install.sh
```

Flags: `-allow a,b` adds commands to the allow-list (which is also how a
sensitive command such as `python3` or `sudo` is permitted), `-disable a,b`
denies them outright, `-strict` blocks every command that is not allow-listed
instead of running it audited, `-allow-sudo` answers sudo's credential probes (`sudo -v`, `sudo -n -l
mkdir`) with success so an installer that gates on sudo access proceeds — `sudo
CMD` still runs `CMD` confined, never escalated — `-urls p1,p2` sets the URL prefixes `curl`/`wget` may reach
(replacing the default, which is the part of a release download that is the
same for everyone: `github.com`, `raw.githubusercontent.com`,
`objects.githubusercontent.com` — a vendor's own release host is not, and is
yours to name),
`-urls-github` adds the GitHub release hosts on top (github.com, api.github.com,
the raw/codeload/objects/release-assets hosts — enough for any godownloader or
goreleaser installer), `-git-hosts h1,h2` sets the hosts `git` may
clone/fetch/push to over any transport (default GitHub, GitLab and Bitbucket;
a subdomain of a listed host counts), `-audit
FILE|-` writes the audit log (default stderr), `-data N` captures N bytes of
each command's stdin/stdout, `-root DIR` picks the sandbox directory (it is emptied on every run, so it must be missing, empty, or a previous sandbox — anything else is refused rather than deleted), and
`-policy FILE` / `-init-policy FILE` read and generate the YAML policy file
below. Anything after the script is passed through as `$1…`. See
[Running any script from the command line](#running-any-script-from-the-command-line)
for a walk-through of the Fly.io run.

For anything beyond a couple of flags, put the whole policy in a YAML file
instead. `-init-policy` writes a commented boilerplate one to fill in:

```bash
smash -init-policy policy.yaml   # every knob, documented, commented out at its default
smash -policy policy.yaml        # script, args and policy all come from the file
```

A policy file reaches parts the flags do not — mocks, target-OS emulation,
injected headers, extra environment, the response and per-request caps — and it
is the artefact you check in next to the installer, review, and diff when it
changes. See [The policy file](#the-policy-file).

## What the sandbox does

mvdan/sh interprets only the shell *language*; every external command
(`uname`, `curl`, `tar`, …) runs as a real host binary. So an installer runs
end to end and leaves a real, working install behind — inside the root.
`TestUVInstallerAuditTrail` runs uv's installer that way with no network (the
release download and `sha256sum` are mocked), then executes the installed `uv`
from inside the sandbox and watches its audit trail:

```yaml
- name: curl
  resources: [fetch url https://releases.astral.sh/github/uv/releases/download/0.12.9/uv-aarch64-apple-darwin.tar.gz, write path $TMPDIR/tmp.X/input.tar.gz]
  command: curl -sSfL … -o …
  exit: 0
- name: tar
  resources: [read archive $TMPDIR/tmp.X/input.tar.gz, chdir path $TMPDIR/tmp.X]
  command: tar --no-same-owner --strip-components 1 -C … -xf …
  exit: 0
- name: mv
  resources: [move path $TMPDIR/tmp.X/uv → ~/.local/bin/tmp.Y]
  command: mv … …
  exit: 0
- name: chmod
  resources: [apply mode +x, modify path ~/.local/bin/tmp.Y/uv]
  command: chmod +x …
  exit: 0
```

(`duration` and `params` lines elided; the script's own output, `everything's
installed!`, goes to stdout.)

The sandbox is enforced in [`internal/sandbox`](internal/sandbox)
by a stack of `interp.ExecHandlers` middlewares:

- **Command gate** — most commands an installer runs are neither interesting
  nor dangerous (`df`, `sw_vers`, `lsb_release`), so by default they run and
  are simply *audited*: `[sandbox] unlisted command: df` on stderr, and
  `unlisted: true` on the record, so a reader can filter for what the
  allow-list did not anticipate. The allow-list (`DefaultAllowList`) is the
  set of known commands that run without remark. A **sensitive** command
  (`DefaultSensitiveList`: `sudo`/`su`, shells given a file, `python3`/`perl`/
  `ruby`/`node`, `dpkg`/`rpm`/`installer`, `launchctl`/`systemctl`/`crontab`,
  `kill`, …) is blocked with `exit 127` and `[sandbox] blocked command: …
  (sensitive; allow-list it to permit)` — those escalate, write outside the
  root, or would run arbitrary code past every guard, so each one is an
  explicit grant via `-allow`. `-strict` (`Config.Strict`) restores
  allow-list-only: anything unlisted is blocked.
- **Scoped dir** — `HOME`, `PATH` (and tool knobs such as `UV_INSTALL_DIR`) all
  point inside the sandbox root, so nothing lands in the real home directory.
  The interpreter also sets `BASH_VERSION` (unexported, like bash), so the
  "pipe me to bash, not sh" guard in nvm/brew/rvm-style installers passes.
  A script whose shebang names `sh` (or a `sh -c` sub-script, or
  `Config.Posix`) additionally sees `POSIXLY_CORRECT=y`, as bash does in POSIX
  mode — `/bin/sh` on macOS — so the opposite guard (Starship: "not under
  non-POSIX bash") passes too, while brew's "not in POSIX mode" check still
  holds for a bash script.
- **Escape hatch** — a program that resolves *inside* the sandbox may run
  (resolved against the runner's `PATH`, never the host's), which is how the
  freshly-installed `uv` executes while a host-global `uv` would not. It runs
  flagged `in-root: true` on the audit record, never silently. The hatch is
  **not** a way to run anything, because the gate reasons about `argv[0]` while
  the kernel runs whatever a `#!` line names — and writing an executable into
  the root is not an exotic capability, it is what every installer does. So a
  script there is judged by the interpreter its shebang names (`#!/usr/bin/env
  python3` is `python3`: sensitive, blocked until allow-listed), and a *shell*
  script is parsed and run in the confined sub-runner rather than handed to a
  real shell — the same treatment `sh -c` gets, for the same reason, so an
  installer's shell wrapper still works while every command inside it is
  re-enforced. `TestInRootScriptCannotEscapeStrictOrDeny` pins it: under
  `-strict` with the shells disabled, `printf '#!/bin/bash\n…' > $ROOT/x;
  chmod +x $ROOT/x; $ROOT/x` is refused, naming `/bin/bash`.

**In-process network.** `curl` and `wget` are *not* shelled out to host
binaries (which could reach any URL). [`network.go`](internal/sandbox/network.go)
intercepts every `command.Downloader` in the exec middleware, takes its parsed
`Request`, and drives a
configurable `http.Client` — so the URL allow-list, redirect policy (re-checked
per hop), timeout, size cap, header injection and transport (proxy/TLS) are all
enforced in Go. The `releases.astral.sh → release-assets.githubusercontent.com`
redirect during a real uv install exercises exactly that path: an allow-list
that names only the first host is refused at the hop.

The allow-list matches URLs **structurally**, not as text: scheme and host
(with any explicit non-default port) exactly, and the entry's path as a
whole-segment prefix — so `https://example.com/pkg` admits
`https://example.com/pkg/v1` but not `https://example.com/pkgs`, and never
`https://example.com.evil.test/pkg`. Two shapes are refused before the list is
even consulted, because both let a URL *read* as one host and *resolve* as
another: **userinfo** (`https://github.com@evil.test/x` — the client dials
`evil.test`) and a **`.`/`..` path segment**, raw or percent-encoded, which the
server normalises after the check. `TestPolicyRejectsAmbiguousURLs` pins them,
and the same predicate runs on every redirect hop. `Policy.Validate` reports an
entry that is not a URL prefix at all, so a mistyped `-urls` says so instead of
silently matching nothing — the CLI calls it.

Because the write is the sandbox's own, it is confined: `curl -o` outside the
root is refused (`TestFetchCannotWriteOutsideRoot`), even from an allow-listed
URL. That is the one filesystem promise the in-process design can actually
keep; a host binary's writes are not scoped (see the soft boundary below).

**Downloader detection is intercepted too.** The installer picks its downloader
with `command -v curl` — a shell builtin that resolves against the *real* PATH,
so it would otherwise need curl/wget to exist on the host. A `CallHandler`
([`detectionCallHandler`](internal/sandbox/detection.go)) intercepts
that probe and fakes a path for downloaders only, leaving `command -v sha256sum`, `ldd`, …
honest. The sandbox now needs no curl/wget on the host at all.

**Raw TCP/UDP detection.** `curl`/`wget` aren't the only way out — bash can open
a socket directly with `/dev/tcp/HOST/PORT`. Those are *file opens*, so an
`OpenHandler` ([`netDetectOpenMiddleware`](internal/sandbox/devnet.go))
sees every one, logs it, and denies it (the comment there shows how to dial an
allow-listed endpoint instead). `TestDevTCPDenied` probes the cloud-metadata IP and gets caught:

```
[sandbox] tcp socket attempt detected: 169.254.169.254:80 (denied)
/dev/tcp/169.254.169.254/80: [sandbox] raw network device access denied
```

> **Soft boundary.** The *exec* side is language-level only. An allow-listed
> or unlisted command (`tar`, `sed`, `df`, …) could still be abused, and host
> `/bin` is on `PATH`. The egress guard knows the network tools it *models* —
> a broad set, but `busybox wget`, `httpie`, `xh` and anything else outside the
> registry are unlisted, and unlisted commands run. **For a script you do not
> trust, use `-strict`**, which blocks everything that is not allow-listed and
> turns that residual risk into an explicit list. Filesystem scope is
> convention rather than enforcement in the same way: `HOME`, `TMPDIR` and
> `PATH` point inside the root, but nothing stops an allow-listed binary
> writing elsewhere (`PathMutator.Targets` is the hook for that guard; see
> [`docs/fs-state-plan.md`](docs/fs-state-plan.md)).
> `TestUVInstallerAuditTrail` ends by running `uv python list` — a network
> subcommand of the just-installed binary — and the egress guard denies it,
> because `uv` is a modelled package manager; but that is argv inspection, not
> OS confinement.
> For real isolation, add OS confinement (below).

## Tests

`just test` runs the suite — 144 tests across `cmd/smash`, `internal/command`,
`internal/policy` and `internal/sandbox`, including a dozen real installers
replayed end to end with no network, plus the parser, the command gate, the
in-process curl/wget layer and the patches to mvdan/sh. What each test pins is
catalogued in [`docs/tests.md`](docs/tests.md).

## Command model

Command handling is one small type system, not scattered `switch`es. A command
family is a concrete type implementing `Command` (`Names() + Parse()`), and extra
behavior is opt-in via capability interfaces the guards discover by type
assertion:

| Interface | Method | Implemented by | Consumed by |
|---|---|---|---|
| `Command` | `Names`, `Parse` | every command type | `command.Registry` |
| `Networked` | `Egress` | `Curl`, `Wget`, `Openssl`, `SSH`, `Scp`, `Rsync`, `Netcat`, `Git`, `Perl`, `Python`, `Gpg`, `NetTool` (dig/whois/ping/telnet/svn/docker/mysql/…), `PackageManager` (apt/yum/apk/brew/pip/npm/cargo/…) | egress guard |
| `Describer` | `Resources` | commands whose resources need logic (grep/sed/tar, find, sh, rsync, install, gpg, `NetTool`, `PackageManager`); tag-driven params describe themselves | audit log |
| `Downloader` | `Request` | `Curl`, `Wget` | in-process HTTP |
| `Wrapper` | `Unwrap` | `Sudo` (sudo/doas, probe-aware), `PrefixWrapper` (env/timeout/nice/…), `Xargs`, `Find` | unwrap |
| `ScriptRunner` | `DashC` | `Shell` | `sh -c` interpreter |
| `Structured` | `Params` | `Curl`, `Wget`, `Openssl`, `SSH`, `Scp`, `Rsync`, `Perl`, `Python`, `Base64`, `Find`, the permission commands | typed params / logging |
| `PathMutator` | `Targets` | `Chmod`, `Chown`, `Chgrp`, `Chattr`, `Setfacl`, `Chflags`, `Chcon`, `InstallCommand` | a path-scope guard (not yet wired) |
| `FileOperator` | `FileChanges` | `FileTool` (rm/rmdir/mkdir/touch/truncate/shred), `TransferTool` (mv/cp/ln), `Mktemp`, `Tee`, `Unzip`, `Compress`, `Dd`, `Tar`, `Sed`, `Rsync`, `Scp` | monitoring: the `files:` audit line |
| `Builtin` | `builtin` | `Grep`, `Sed`, `Awk`, `Tar`, `Base64`, `Find`, `Gpg`, the permission commands, `Tool` | allow-list derivation |

Adding `aws`, `kubectl`, or a new wrapper is a type in the registry — the guards
don't change. Some types earn their keep by capturing real quirks:

- `curl` and `wget` are **separate** types: `wget -O` is the output file while
  `wget -o` is a *logfile* (≈ the opposite of curl), and wget follows redirects
  by default.
- `ssh`, `scp`/`sftp`, and `rsync` are three types because their flags
  disagree: `-p` is ssh's port but scp's preserve-times, and rsync's remote
  spec is an operand (`host:path`, `host::module`, `rsync://`) rather than a
  destination argument.
- `perl` and `python` are `Networked` on a **heuristic**, because the
  interpreters are escape hatches in their own right. For perl: `-M`/`-m`
  network modules, module names or URLs inside `-e` code. For python: a
  networked `-m` module — the one-line servers, `python3 -m http.server 8000`
  and its `SimpleHTTPServer` ancestor, plus `pip`/`venv` — or, inside `-c`
  code, the address a socket one-liner dials, a URL, or an imported network
  module. So the socket/`subprocess` reverse shell is denied by the endpoint it
  reaches (`network egress denied: python3 → 10.0.0.1:1234`), not merely by its
  interpreter. A script file (`perl fetch.pl`, `python fetch.py`) is opaque, so
  there the command gate — not the egress guard — is the real one: both are on
  the sensitive list, blocked until allow-listed, and allow-listing the
  interpreter still leaves the egress guard in front of it.
- The long tail of network tools (`dig`, `whois`, `ping`, `telnet`, `aria2c`,
  `svn`, `hg`, `docker`, `mysql`, `psql`, …) is one data-driven `NetTool` type
  in [`nettools.go`](internal/command/nettools.go): egress is
  the `@server` or first operand, gated by a subcommand set (`docker pull` yes,
  `docker ps` no) or a host flag (`mysql -h` yes, local socket no); `telnet`
  takes both operands, so it is logged and gated as `host:port`.
- `openssl` is three tools in one and is modelled as such: `s_client` is
  egress, `dgst` is an offline digest (`-sign KEY` takes a key file there, but
  `-sign` is a bare flag for `rsautl`, so `dgst` gets its own `Spec`), and
  `enc`/`pkeyutl`/`smime` **encrypt and decrypt**. `OpensslParams` carries
  `In`/`Out`, `InKey`/`KeyFile`, `Decrypt`/`Encrypt` and `Cipher()`, and its
  audit line names the transform: `openssl: decrypt path f.enc, write path f.txt`.
  Passphrases (`-pass`, `-k`, `-K`) are secret fields, and `-hmac` in the
  pass-through `Rest` is redacted too.
- `gpg` is a `Builtin` **and** `Networked`: offline `--verify` is what
  installers need, but `--recv-keys`/`--keyserver` reach out, so the egress
  guard denies those even when `gpg` is allow-listed.
- **File operations are differentiated for monitoring**
  ([`fileops.go`](internal/command/fileops.go)): a
  `FileChange{Op, Path, From, Recursive}` says *how* the filesystem changes —
  `delete /tmp/x (recursive)`, `move a → b`, `copy src → dst`,
  `link target → name`, `extract uv.tgz → /opt`, `write f.gz` + `delete f` for
  `gzip`, `write /dev/zero → /dev/sda` for `dd`. `p.FileChanges()` is the one
  call a monitor makes: it uses the command's `FileOperator`, else its
  `PathMutator` targets (`chmod` → `mode f`), else its resource tags
  (`curl -o f` → `write f`, `sed -i` → `write f`). Read-only commands return
  nothing. Two data-driven types cover most tools — `FileTool` (one op per
  operand) and `TransferTool` (sources → destination) — and every audit record
  carries a `files:` line (`TestFileChanges`).
- The permission commands (`chmod`, `chown`, `chgrp`, `chattr`, `setfacl`,
  `chflags`, `chcon`, `install`) in [`perms.go`](internal/command/perms.go)
  are `PathMutator`s: `Targets` reports the paths an invocation changes and
  whether it recurses — including the awkward `chmod -x f` / `chattr -i f`
  forms whose mode looks like a flag. Nothing consumes `Targets` yet; it is the
  hook for a path-scope guard.
- Package managers (`apt`/`apt-get`, `yum`/`dnf`, `zypper`, `apk`, `pacman`,
  `brew`, `nix`, `snap`, `flatpak`, `pip`/`uv`, `npm`/`yarn`, `gem`, `cargo`,
  `go`, `composer`, `cpan`, …) are one data-driven `PackageManager` type in
  [`packages.go`](internal/command/packages.go): each entry
  names the subcommands (or flags, for `pacman -S`) that reach the network, and
  any URL operand always does. `apt-get -y install x` is an egress denial;
  `apt-cache policy x` and `dpkg -i ./x.deb` are not.
- `xargs` is not a `PrefixWrapper`: its `-i` replace-string is optional-attached
  (`-i{}`), so it must not consume the following arg (`xargs -i rm` → inner `rm`),
  and with no command it defaults to `echo`.
- `find` is a `Builtin` that *also* implements `Wrapper`: plain `find` lists
  files, but `-exec`/`-execdir`/`-ok`/`-okdir` run commands, so the exec'd command
  is peeled out and re-enforced — `find . -exec curl https://evil {} \;` is caught
  by the URL allow-list, not run.
- `Builtin` marks the safe local tools (`grep`/`sed`/`awk`/`tar`/… in
  [`builtins.go`](internal/command/builtins.go));
  `command.BuiltinNames()` derives allow-lists from the registry instead of a
  hand-kept string list. The `Registry` refuses duplicate names at construction
  (`TestRegistryRejectsDuplicates`), so a builtin can never shadow a networked
  or wrapper command — the bug that once let `env … curl` run unconfined.

**Every command describes what it touches** ([`resource.go`](internal/command/resource.go)):
`Parse(argv).Describe()` renders `name: action kind value, …` — e.g.
`curl: fetch url https://x/y, write path out.tgz` or
`chmod: apply mode 755, modify path a`. Tag-driven params add a
`resource:"kind,action[,stream]"` tag per field; the optional stream names what
is used when the field is empty, so a tool fed by a pipe says so:
`base64: read stdin`, `curl: … write stdout`, `sh: run stdin`. Commands whose
resources need logic implement `Describer` ([`describe.go`](internal/command/describe.go)):
`tar` (archive vs members, by direction), `find` (`-exec` as a run command),
`install` (sources read, destination written), `rsync`/`scp` (remote vs local).
Header, cookie and password values are never resources, and the command line
and params in a record are **redacted** (`secret:"true"` fields, well-known
secret flags, a command's own `SecretFlags`) before they are logged.

**Seeing the params and the data.** Set `Config.Auditor` and every executed
command produces an `AuditRecord`: the normalized command line, its typed
params, its resources, exit status and duration. Set `Config.AuditData` to a
byte cap and the record also carries what flowed through the command's stdin
and stdout — so for `printf hi | base64` you see both the params and the value:

```yaml
- name: base64
  resources: [read stdin]
  command: base64 -d
  params: !Base64Params {Decode: true}
  exit: 0
  duration: 3ms
  stdin: {bytes: 4, data: "aGk="}
  stdout: {bytes: 2, data: "hi"}
```

`TextAuditor(w)` writes that form: a YAML stream with one sequence item per
record, so the whole log is a document `yq` can query
(`yq '.[] | select(.exit != 0) | .name' audit.yaml`). The keys mirror
`AuditRecord`: `exit` is the status when the program ran, `error` the message
when it could not, `reason` the sandbox's own diagnostic when it failed the
command. `params` carries the type as a local tag and lists only the fields
that are set; a `files:` line follows when the command changes the filesystem
in a way `resources` doesn't already say (`delete ~/.cache (recursive)`).
`wrappers: [sudo, env]` names the wrappers the command was reached through —
enforcement forgets them on purpose, since a guard must see the real command,
but the log must not: `sudo rm -rf /` and `rm -rf /` are the same command to
the gate and very different events to a reader. `unlisted: true` and
`in-root: true` say how a command got past the gate.
Captured data is always double-quoted; everything else is plain unless YAML
requires quoting. Pass `ShortPaths(cfg)` and paths inside the sandbox are
written as `~/…`, `$TMPDIR/…` and `$ROOT/…` — the CLI does — while the records
keep the full paths. Implement `Auditor` yourself for JSON or a database.

**The shell's own opens.** Redirections (`> f`, `>> f`, `< f`, `exec 3< f`)
and `source` are resolved by the interpreter, not by a command, so they never
reach the exec chain — `echo "$TOKEN" > ~/.netrc` would otherwise leave no
trace. An `Auditor` that also implements `OpenAuditor` receives one
`OpenRecord` per shell open (path, `read`/`write`/`append`, the raw flags, and
the error if it failed); `TextAuditor` does, and renders it as
`- name: shell` / `resources: [append path ~/.bashrc]`, with an `error:` line
when the open failed. `/dev/null` is skipped (`TestAuditShellOpens`). Capture works for host binaries and the in-process `curl` alike: the
middleware hands the command a context whose `HandlerContext` carries tee'd
streams (`TestAuditDataCapture`, `TestWithHandlerContext`, `TestAuditLog`,
`TestDescribe`, `TestRedact`).

**Typed, reversible params** (`internal/command/params.go`): every `ParsedCommand` renders back to
a command line via `String()`, and commands implementing `Structured` expose a
named-field struct — `CurlParams{URL, Output, Headers, FailFast, …}` — that you
can read, edit, and stringify. The structs are **tag-driven**: each field
declares its flag once (`` Follow bool `flag:"-L,--location"` ``), and
[`bind.go`](internal/command/bind.go) derives the reader, the
renderer, *and* the command's parse `Spec` from those tags, so the parser and
the params cannot drift apart. `find` stays hand-written (it is order-sensitive). `p.TypedParams()` returns the typed struct where
available, else the generic form. `curl -fsSL https://x -o out` ⇄
`CurlParams{...}` ⇄ `"curl -sSfL -o out https://x"` round-trips
(`TestCurlParams`).

## One command parser, one egress guard

`curl`/`wget` and `/dev/tcp` aren't the only ways out — `openssl s_client`, `ssh`,
`nc`, and `git clone` all egress too. Rather than a bespoke check per command,
[`internal/command`](internal/command) gives each family a
declarative `Spec` (value flags, short-flag clustering, subcommands).
`command.Parse` returns a structured `ParsedCommand` (flags, operands,
subcommand) whose **`Egress()`** answers the one question the guards need: does
*this* invocation reach out, and where? A single `egressGuardMiddleware`
consumes it to deny any network-capable command whose
target isn't allow-listed — so `openssl` stays usable for `dgst -sha3-256`
checksums but `openssl s_client -connect …`, `ssh`, `nc`, and `git clone` to
off-list hosts are all denied from one place. A remote *name* (`git fetch
origin tag v1`, as nvm does after its clone) is resolved through the
repository's `.git/config` and judged by the URL it points at, so a remote
redirected off-list by any means is still caught when it is used. `git` is
judged **only** by `Policy.GitHosts` (plus `file://`, which reaches no
network): the URL allow-list deliberately does not grant it, because "the
in-process client may GET this URL" and "git may push a repository there" are
different questions, and conflating them would stop `-git-hosts` narrowing
anything `-urls` had already named. Covered by
`TestParseIndicators`, `TestParseFlags`, `TestEgressGuardGeneralizes`, and
`TestGitNamedRemote`.

## Closing the `sh -c` escape hatch

An allowed shell running an arbitrary `-c` string (`sudo -E sh -c '…'`, as
get-docker uses) would run everything *outside* the sandbox. `shInterpMiddleware`
([`shinterp.go`](internal/sandbox/shinterp.go)) instead parses the `-c` string
and re-runs it in a **confined sub-runner** built from the same config, so every
inner command is re-enforced — nesting is depth-capped and the whole run is
bounded by a **context timeout** (`TestExecutionTimeout`, `TestShCInterpretedConfined`).

## Seeing through wrappers

A name-based guard is fooled by wrapper commands: `sudo rm`, `env curl`,
`timeout 5 openssl s_client` all smuggle the real command past the allow-list,
the curl interception, and the openssl guard. `unwrapMiddleware`
([`middleware.go`](internal/sandbox/middleware.go)) peels every
`Wrapper` in the registry (`sudo`, `doas`, `env`, `nice`, `ionice`, `nohup`,
`setsid`, `stdbuf`, `timeout`, `command`, `time`, `watch`, `xargs`, `find -exec`)
— handling each wrapper's
value-consuming flags, `env VAR=val` assignments, and `timeout`'s positional
duration — **before** any guard runs, so enforcement always sees the real
command. Stripping `sudo`/`doas` is also a feature: the inner command runs
confined instead of really escalating. `TestUnwrap` covers the parsing;
`TestWrappersCannotSmuggle` proves `env curl`, `timeout openssl s_client`, and
`sudo apt-get` are all still caught. A sudo *credential probe* runs nothing
(`sudo -v`, `sudo -n -l mkdir`, `sudo -K`): `Sudo.Unwrap` leaves it whole, so it
falls to the command gate, where `sudo` is sensitive and blocked — unless `Config.AllowSudo` (`-allow-sudo`)
is set, when `sudoGrantMiddleware` answers it with success, as passwordless
sudo would, so installers gated on it proceed while every `sudo CMD` is still
de-escalated (`TestAllowSudo`). A `sleep` cap (`TestSleepCapped`) stops a
script burning wall-time.

## Emulating a target OS (get-docker)

Docker's [`get-docker`](fixtures/get-docker) is Linux-only and bails at `uname`
on macOS. An opt-in `Emulation` ([`emulate.go`](internal/sandbox/emulate.go))
fakes a Linux `uname` and serves a virtual `/etc/os-release` — wired through the
**stat**, **access**, and **open** handlers so `[ -f ]`, `[ -r ]`, and
`. /etc/os-release` all see it. `TestGetDockerLinuxContained`: under Ubuntu
emulation get-docker clears OS + distro detection, its 20s warning is capped, it
advances into the Debian install path, and the command gate contains it at the
first sensitive package tool (`dpkg`) — nothing installed, no real sudo,
no wall-time burned.

## Hardening beyond in-process

The chosen level here is in-process. To make even allow-listed real binaries
unable to escape, wrap the mvdan/sh runner in OS-level confinement:

- **macOS** — `sandbox-exec` (Seatbelt) profile restricting file + network.
- **Linux** — user namespaces + `seccomp` (e.g. via `landlock`/`bubblewrap`).
- **Either** — run inside a container or microVM (closest to what
  [Vercel Sandbox](https://vercel.com/docs/vercel-sandbox) provides).

## Running any script from the command line

`cmd/smash/main.go` doubles as a CLI: give it a script (local path or `http(s)://`
URL, fetched like `curl -fsS`) and a policy and it runs it in a fresh `./sandbox` root with `HOME` and `TMPDIR` inside, writing an audit log.
This is how [`fixtures/fly.sh`](fixtures/fly.sh) (the Fly.io installer) was run:

```bash
go run ./cmd/smash \
  -urls https://api.fly.io/,https://github.com/superfly/,https://release-assets.githubusercontent.com \
  -audit fly-audit.log -data 200 \
  fixtures/fly.sh --non-interactive
```

The first attempt was refused at the redirect hop — GitHub now serves release
assets from `release-assets.githubusercontent.com`, which was not on the list —
and the audit log showed exactly where. With it allowed, the log reads as the
installer's file-change story: `create …/.fly/bin`, `fetch url …`, `write
…/flyctl.tar.gz`, `extract … → …/.fly/tmp`, `mode flyctl`, `move flyctl →
…/bin/flyctl`, `delete flyctl.tar.gz`, `link flyctl → fly`, then the real
`flyctl version -s shell` runs from inside the root. Flags: `-allow`,
`-disable`, `-urls`, `-audit FILE|-`, `-data N`, `-root DIR`, `-policy FILE`;
anything after the script is passed as `$1…`. The same run as a policy file is
in [The policy file](#the-policy-file). `TestFlyInstallerAuditTrail` replays the same
installer with **no network** by mocking both curls (the download mock writes a
real tarball) and asserts the audit trail.

## The policy file

Flags stop scaling once a policy has more than a few rules, and they cannot
express the parts that were previously Go-only — mocks, target-OS emulation,
injected headers. `-policy FILE` reads the whole run from one YAML file, and
`-init-policy FILE` writes a commented boilerplate one with every key present,
documented, and commented out at its default:

```bash
smash -init-policy policy.yaml
# edit it, then:
smash -policy policy.yaml
```

The boilerplate is a no-op unedited (`TestTemplateIsANoOp`), and the section
headers are live and empty, so setting a key is a matter of deleting a `#`
rather than remembering the nesting. Unknown keys are **rejected** — a mistyped
rule would otherwise leave a gate open silently. Here is the fly.sh run from
above, plus the parts flags cannot reach:

```yaml
script: fixtures/fly.sh
args: [--non-interactive]
root: sandbox                 # recreated each run; HOME and TMPDIR live inside

audit:
  path: fly-audit.log         # "-" is stderr, "" turns it off
  data: 200                   # bytes of stdin/stdout captured per command

commands:
  allow: [python3]            # widens the default allow-list; the way to permit a sensitive command
  disable: [rm, rmdir]        # blocked outright, after unwrapping: sudo rm, find -exec rm, sh -c 'rm …'
  sensitive: [ssh]            # blocked even though unlisted commands otherwise run
  # replace: true             # make allow/sensitive REPLACE the built-in lists rather than widen them

network:
  urls:                       # replaces the default list; every entry needs a scheme
    - https://api.fly.io/
    - https://github.com/superfly/
    - https://release-assets.githubusercontent.com
  github: false               # also append the rest of the GitHub release hosts (-urls-github)
  git-hosts: [github.com]     # where git may clone/fetch/push, over any transport
  methods: [GET, HEAD]
  max-response: 200MiB        # a plain number is bytes; KiB/MiB/GiB and KB/MB/GB both work
  timeout: 60s
  headers:                    # injected into every request — the secret stays out of the script
    Authorization: Bearer …

emulation:                    # run a Linux-only installer on another host
  uname-os: Linux
  uname-arch: x86_64
  files:
    /etc/os-release: |
      ID=ubuntu

mocks:                        # checked before the network layer and the allow-list
  - match: {args: [uname, -s]}
    stdout: "Linux\n"
  - match:                    # several criteria in one block must ALL hold
      name: [curl, wget]
      resource: {kind: url, value: "https://releases.astral.sh/*"}
    stdout: ""
  - match: {glob: "frobnicate *"}
    stderr: "frobnicate: boom\n"
    exit: 3
  - match: {prefix: [git, clone]}
    stdout: "cloned\n"

strict: false                 # block everything not allow-listed, rather than run it flagged
allow-sudo: false
timeout: 2m
env:                          # layered over the sandbox's own HOME/TMPDIR/PATH/SHELL/TERM
  UV_INSTALL_DIR: /home/.local/bin
```

A `match:` block spells the matchers from [`control.go`](internal/sandbox/control.go):
`args` (exact argv), `prefix`, `name`, `glob` (over the whole command line),
and `resource` (a `url`/`path`/`host`/… the invocation touches, matched by
glob). Several in one block compose with `And`. The dynamic ones — `MatchFunc`
and `Mock.Respond` — stay Go-only; there is no YAML spelling for a predicate.

**Flags override the file, but only when typed.** The override is keyed off
which flags actually appeared on the command line, not their values, so a
policy's `strict: true` survives an absent `-strict` (whose default is `false`)
and is turned off only by an explicit `-strict=false`:

```bash
smash -policy policy.yaml                          # the file's policy
smash -policy policy.yaml -strict other.sh         # …with strict forced on, on another script
```

Naming a script on the command line replaces the file's `script:` **and** its
`args:` together, so a new script never inherits arguments meant for the old
one. Relative paths in the file resolve against the directory `smash` runs in,
the same as the flags. Two things the file cannot loosen: an entry in `urls`
with no scheme is now an error rather than a rule that silently matches
nothing, and `urls: []` written out means *deny every fetch* — while `urls:`
with nothing under it is a half-finished key and keeps the defaults.

## Using the sandbox from Go

The CLI is a thin client of two packages. `sandbox.Config` carries everything a
run needs; `NewConfig` fills in the defaults, and every field is open
for widening or replacing:

```go
cfg := sandbox.NewConfig(root, home, env)          // DefaultPolicy + DefaultAllowList + DefaultSensitiveList
cfg.Allowed = cfg.Allowed.With("python3")            // permit a sensitive command (df, lsb_release, … already run, audited)
cfg.Strict = true                                    // or: block anything that is not allow-listed
cfg.Network.AllowedPrefixes = []string{"https://internal.example/"}
cfg.Network.InjectHeaders = map[string]string{"Authorization": "Bearer …"}
cfg.Emulation = sandbox.Emulation{UnameOS: "Linux", Files: map[string]string{"/etc/os-release": "ID=ubuntu\n"}}
cfg.Timeout = 30 * time.Second
cfg.Auditor = sandbox.TextAuditor(os.Stderr)        // one YAML record ("- name: curl …") per command
cfg.AuditData = 4096                                // also capture stdin/stdout, up to 4 KiB each
err := sandbox.Run(cfg, "install.sh", script)
```

Variables have two views. `RunVars` is `Run` plus the final variable table, so
a post-run audit sees resolved values (`APP_NAME=uv`, the download URL the
branch actually picked). `Assignments` walks the AST without running anything
and lists every `NAME=value` as written, flagging the ones with no expansion:

```go
vars, err := sandbox.RunVars(cfg, "install.sh", script)
fmt.Println(vars["ARTIFACT_DOWNLOAD_URLS"].String())     // resolved
as, _ := sandbox.Assignments("install.sh", script)
// {Name:APP_NAME Value:uv Line:26 Static:true}
// {Name:ARTIFACT_DOWNLOAD_URLS Value:"$UV_DOWNLOAD_URL" Line:28}
```

**Disabling commands and mocking responses**
([`control.go`](internal/sandbox/control.go)):

```go
cfg.Disable("rm", "rmdir")   // never runs: not via sudo, find -exec, sh -c, or from inside Root
cfg.AllowSudo = true         // `sudo -v` / `sudo -n -l CMD` succeed; `sudo CMD` still runs CMD confined

uname := cfg.Mock(sandbox.MatchArgs("uname", "-s"), "Linux\n", "", 0)
cfg.Mock(sandbox.MatchName("curl").And(sandbox.MatchResource("url", "https://releases.astral.sh/*")), "", "", 0)
cfg.Mock(sandbox.MatchGlob("frobnicate *"), "", "frobnicate: boom\n", 3)
cfg.MockFunc(sandbox.MatchPrefix("version"), func(p command.ParsedCommand) (string, string, int) {
    return "v" + p.Operands[0] + "\n", "", 0
})
err := sandbox.Run(cfg, "t", script)
uname.Called()   // 1 — and uname.Calls()[0].TypedParams() for the parsed invocation
```

Matchers select on name, exact argv, argv prefix, a glob over the command
line, a resource of a kind (`url`, `path`, `host`, …) matching a glob, or any
predicate (`MatchFunc`), with `And`/`Or`. A mock supplies stdout, stderr and
the exit code (or computes them), records its calls, and runs before the
network layer and the allow-list — so a mocked `curl` never touches the
network. Both act on the real command after unwrapping, and denial beats
mocking (`TestDisable`, `TestMocks`).

`command` is independent of mvdan/sh: `command.Parse(argv)` gives you the
parsed form, `Egress()`, `TypedParams()`, and `Unwrap` without running anything.

## Layout

The file-by-file tour — `cmd/smash`, `internal/policy`, `internal/command`,
`internal/sandbox`, and the vendored installers under `fixtures/` — is in
[`docs/layout.md`](docs/layout.md).

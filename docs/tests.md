# Tests — including a second, gnarlier installer

`go test ./...` (144 tests across `cmd/smash`, `internal/command`, `internal/policy` and
`internal/sandbox`) covers the parser, the command gate (`TestGate*`: unlisted
runs audited, sensitive blocked, `-allow` lifts it, `-strict` blocks),
the in-process curl/wget requests +
URL allow-list, redirect handling, the downloader-detection
interception, and the sandbox against a **second** real installer,
[`rvm-installer`](../fixtures/rvm-installer) — a much heavier bash script (arrays,
`[[ ]]`, `extglob`, `errtrace`, backslash-escaped commands).

Security regressions also pin ownership-marker root cleanup, strict-mode denial
of native in-root binaries and PATH shadows, explicit Git grants and rewrite
denials, and bounded curl request bodies.

## Running them

```bash
just test                     # go test -count=1 ./...
just test -run TestNoclobber  # extra args go to `go test`
just race                     # under the race detector (a CI gate)
just ci                       # everything CI checks: fmt, tidy, vet, build, test, race, cross
```

A fresh clone needs `just sync` (or any recipe that depends on it) first: the
build replaces `mvdan.cc/sh` with the generated, untracked `third_party/sh`.

## What the suite pins

- **`TestUVInstallerAuditTrail`** / **`TestFlyInstallerAuditTrail`** — two real
  installers run to completion with **no network**: the downloads are mocked to
  write real tarballs holding fake binaries (and, for uv, `sha256sum` is mocked
  to agree with the installer's pinned checksum), the installed "binary" then
  runs from inside the root, and the audit trail reads as the install's
  file-change story. The uv installer's old-style `tar xf …` is what made the
  tar describer accept undashed option bundles.
- **`TestFixturesParseBash`** — mvdan/sh's bash parser accepts every vendored
  installer under `fixtures/` (it reads the directory, so a new fixture is
  parse-checked the moment it lands).
- **`TestGodownloaderInstallersAuditTrail`** — three installers built on the
  godownloader/shlib skeleton (Bearer's `bearer.sh`, trufflehog's `truffle.sh`,
  trivy's `aqua.sh`) run to completion under Linux emulation with no network:
  the tag lookup, tarball and checksums fetches are mocked, the sha256 tool is
  mocked to the fake tarball's real hash, and the `install`ed binary runs from
  inside the root. **`TestGodownloaderChecksumMismatchStopsInstall`** feeds
  each one a wrong checksum and checks nothing is installed.
- **`TestCursorInstallerAuditTrail`** / **`TestPHPInstallerAuditTrail`** /
  **`TestWarpInstallerAuditTrail`** — the remaining "download a binary" installers:
  Cursor's streams `curl | tar` (the mock answers on stdout), php.new's
  backgrounds four `curl … &` downloads and `wait`s, and Warp's exercises the
  versioned layout — the `-w '%{redirect_url}'` version probe, staging via
  `mktemp -d` inside the root, the noclobber lock, the atomic `current` swap —
  and a second run reuses the completed version.
- **`TestNVMScriptInstallAuditTrail`** / **`TestNVMGitInstallHeldByEgressGuard`**
  — nvm in script mode completes with its three raw.githubusercontent.com
  downloads mocked, sources the downloaded `nvm.sh` inside the interpreter and
  installs Node through it; in git mode, with `Policy.GitHosts` cleared, the
  egress guard refuses the clone by its resolved URL and nothing is installed.
- **`TestTerragruntInstallerAuditTrail`** / **`TestTerragruntKeyFetchOffAllowList`**
  — Terragrunt's installer with its default GPG verification: a stand-in `gpg`
  inside the root satisfies the dependency check on hosts without one, and a
  mock answers the key import and signature verify, so the whole path runs.
  With only the release mocked, on a host with gpg, the allow-listed gpg runs
  for real but the signing-key fetch from gruntwork.io is off the URL
  allow-list, so the installer's own guard aborts with nothing installed;
  `--no-verify-sig` is its documented way past.
- **`TestGPGAllowListedKeyserverOpsDenied`** — `gpg` is on the default
  allow-list for that offline work, but every argument that makes it a network
  client (`--keyserver`, `--recv-keys`, `--search-keys`, `--send-keys`,
  `--fetch-keys`, `--refresh-keys`, `--locate-keys`, `--locate-external-keys`,
  `--auto-key-retrieve`, `--recv`) is refused by the egress guard before the
  allow-list is consulted, naming the argument or keyserver; only a keyserver
  on the URL allow-list gets through.
- **`TestStarshipInstallerAuditTrail`** — Starship's POSIX-sh installer has the
  opposite guard from nvm's: it refuses to run under bash unless
  `POSIXLY_CORRECT` is set. Its `#!/usr/bin/env sh` shebang puts the sandbox in
  POSIX mode, which advertises that variable, so the guard passes and the
  mocked tarball download is unpacked into a bin dir under the sandbox HOME and
  the binary runs.
- **`TestBrewInstallerContained`** — Homebrew's installer under Linux emulation
  clears its preflight and stops at its own permission check: the sandbox never
  grants sudo, so `have_sudo_access` fails and brew aborts before any
  `install`/`chown`/`git` — no file change is audited at all. (On macOS it would
  target the real, user-writable `/opt/homebrew`, so the test always emulates
  Linux, and skips as root.)
- **`TestBrewInstallerSudoGranted`** — the same run with `AllowSudo`
  (`-allow-sudo`): the probe is answered, brew clears `have_sudo_access` and
  announces its install plan, and its first privileged step — `sudo install -d
  … /home/linuxbrew/.linuxbrew` — is unwrapped to a confined `install` and
  stopped by the disable list. The grant shows what an installer would do with
  root; it never escalates.
- **`TestRVMInstallerContained`** — run through the full sandbox in **strict**
  mode with the default allow-list, rvm is **contained**: its `\which NAME`
  requirement probes all pass (`which` is allow-listed as a read-only probe),
  then it execs `df`, which isn't, so it fails there — nothing installed, no
  network reached. This is the strict-mode lesson: an allow-list scoped to
  install tooling safely refuses another tool's requirements.
- **`TestRVMDefaultAuditsUnlisted`** — the same run under the default gate:
  `df` is neither allow-listed nor sensitive, so it runs flagged `unlisted`
  (stderr and audit record), and rvm gets as far as the fully widened strict
  run below — to the network boundary — with nothing widened by hand.
- **`TestErrtraceIsAKnownGap`** — pins a real mvdan/sh limitation rvm surfaces:
  `set -o errtrace` is unsupported (reported and skipped, non-fatal).
- **`TestExtraFileDescriptors`** — pins the one change made to the interpreter
  itself. Upstream mvdan/sh rejects any redirection on a descriptor other than
  0/1/2 ("unsupported redirect fd: 3"), which breaks nvm's fd-swap idiom
  `{ v="$(f 3>&1 1>&4)"; } 4>&1` and `f 3>/dev/null`. The copy under
  [`third_party/sh`](../third_party/sh) (generated by `tools/sync-sh.sh` from the
  module cache plus the patches in [`patches/sh/`](../patches/sh), wired in
  with a `replace` directive) adds a
  descriptor table for the shell's own use — builtins, functions, subshells —
  without passing the extra descriptors to exec'd commands. See
  [`patches/sh/README.md`](../patches/sh/README.md).
- **`TestNoclobber`** — the second patch to that copy: `set -o noclobber` /
  `set -C` and `>|`. warp takes its install lock with
  `(set -o noclobber; printf owner > lock)`, which upstream rejects outright.
- **`TestErrexitCompoundBodies`** — the third patch: upstream re-judges `set -e`
  on a compound command's own exit status, so an exempt failure as the last
  statement of an `if` body — terragrunt's
  `! supports_signature_verification "$version" && warn …` — exited the script.
  bash judges only the statement itself: `if`/`{ }`/`for`/`while`/`case` bodies
  inherit their last statement's exemption, while a failing function call or
  subshell still exits. Every case in the test was checked against `/bin/bash`.
- **`TestCommandDefaultPathShim`** — `command -p NAME …` (warp's symlink
  activation) is rejected by mvdan/sh; the CallHandler drops the `-p`, since
  the command gate, not the lookup PATH, decides what may run.
- **`TestTypesetShim` / `TestTypesetShimUnderErrexit`** — a compat shim for
  another mvdan/sh gap: it implements `typeset`/`declare` only as parser
  *keywords*, so a backslash-escaped `\typeset a b c` (rvm line 798) is dispatched
  as a command and fails "unsupported builtin" — exit 2, which aborts scripts
  under `set -e`. Only that escaped/command form reaches the `CallHandler`
  (keyword forms are `DeclClause` and don't), so `shimDeclarationBuiltin` rewrites
  a *bare* escaped declaration to a successful no-op, while passing anything with
  a `name=value` through untouched (never silently dropping an assignment).
- **`TestWiderAllowListAdvancesRVM`** — in strict mode the allow-list is the
  gate: grant every command the parser knows and rvm, having cleared mvdan/sh's
  `\typeset` gap via the typeset shim (below), is still **contained** by the
  allow-list at the command it isn't granted (`df`). How far a script runs is
  governed entirely by what you allow.
- **`TestURLAllowListStopsDownload`** — the network counterpart: even with the
  downloader permitted, a `curl` to an off-list URL is refused in-process by the
  URL allow-list.
- **`TestFullyWidenedRVMHitsNetworkBoundary`** — the end of the widening road
  (still strict): grant *every* command rvm asks for (auto-widening converges on `df`) and it
  clears all requirement checks, downloads, and tries to extract — but with no
  URL on the allow-list every github/api.github fetch is denied, so there's no
  archive and it dies at extraction. **Layered defense:** exhaust the command
  allow-list and the URL allow-list is still the gate.

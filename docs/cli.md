# CLI reference

The `smash` CLI runs a local or remote shell script under a command, network,
filesystem-environment, and audit policy.

```text
smash [flags] SCRIPT|URL [ARGS…]
smash -policy FILE [flags] [SCRIPT [ARGS…]]
smash -profile [flags] SCRIPT|URL [ARGS…]
smash -manifest FILE [flags] SCRIPT|URL [ARGS…]
smash -init-policy FILE
```

## Build and install

The repository replaces `mvdan.cc/sh` with a generated, patched tree under
`third_party/sh`, so `go install …@latest` cannot build this project directly.
From a clone, use:

```bash
just install
```

`just install`, `just build`, `just run`, and the test recipes generate the
tree when it is missing. `just sync` regenerates it explicitly.

## Script input

`SCRIPT` can be a local path or an `http://` or `https://` URL. A URL is fetched
once, before execution, with behavior equivalent to `curl -fsS`: redirects are
followed, HTTP errors fail the command, and the response is size-limited.

That initial fetch is the script the user explicitly requested, so it is not
checked against the run's URL allow-list. Downloads initiated by the script are
checked.

Arguments following the script become its `$1`, `$2`, and so on. If both the
policy and command line name a script, the command-line script and its arguments
replace the policy's `script` and `args` together.

For an interactive terminal run with the default `-audit -`, a `tview` display
is split horizontally. The upper pane is a PTY-backed terminal carrying the
script's stdin, stdout, and stderr, so terminal detection, ANSI control
sequences, line editing, and no-echo prompts keep working. External programs
acquire that PTY as their controlling terminal, and shell opens of `/dev/tty`
are routed there as well. The lower pane is a scrollable stream of Smash audit
events. `F6` switches focus between panes and
`Ctrl-C` stops the run. The completed view remains open for inspection until
Enter, Escape, or `q` is pressed.

The split is disabled automatically if any standard stream is redirected,
input is piped, `$TERM` is empty or `dumb`, the terminal is too small, or the
audit target is a file or disabled.

## Flags

| Flag | Default | Meaning |
|---|---:|---|
| `-policy FILE` | — | Read the base configuration from a YAML policy file |
| `-init-policy FILE` | — | Write a commented policy template and exit; `-` writes to stdout |
| `-profile` | false | Run and write the script SHA-256 plus observed commands, hosts (redirect hops included), and response media types to a manifest |
| `-profile-output FILE` | `<script>.manifest.yaml` | Set the generated manifest path; requires `-profile` |
| `-manifest FILE` | — | Verify the script SHA-256 and restrict commands and hosts to a manifest |
| `-urls p1,p2` | GitHub's common download hosts | Replace the URL prefixes available to in-process `curl` and `wget` |
| `-urls-github` | false | Add GitHub API, raw, codeload, objects, and release-asset hosts |
| `-git-hosts h1,h2` | GitHub, GitLab, Bitbucket | Advisory host checks for explicitly allowed real Git operations |
| `-dns-server IP[:PORT]` | `9.9.9.9:53` | Resolver for initial and in-process HTTP downloads; an empty value uses system DNS |
| `-allow a,b` | — | Add commands to the default allow-list; also permits named sensitive commands |
| `-disable a,b` | — | Deny commands outright after wrapper resolution |
| `-strict` | false | Deny every command not on the allow-list |
| `-allow-sudo` | false | Make sudo/doas credential probes succeed; commands still run without escalation |
| `-allow-in-root` | false | Permit native executables below the run root; this explicitly leaves in-process enforcement |
| `-audit FILE\|-` | `-` | Write the audit stream to a file or stderr; an empty value disables it |
| `-data N` | 0 | Capture at most `N` bytes each of command stdin and stdout |
| `-root DIR` | `sandbox` | Recreated directory used for the run's `HOME`, `TMPDIR`, and leading `PATH` |

Comma-separated list flags do not trim or interpret their entries. URL entries
must include a scheme.

## Profile manifests

Create a behavioral profile while running the script:

```bash
smash -profile install.sh
smash -profile -profile-output install.manifest.yaml install.sh
```

The output is deterministic YAML suitable for review and source control:

```yaml
version: 1
os: linux
script:
  name: install.sh
  sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
commands:
  - curl
  - mkdir
  - tar
hosts:
  - downloads.example.com
```

`os` uses Go's canonical operating-system name (such as `linux` or `darwin`).
Commands, hosts, and media types are sorted and de-duplicated. Profiling is
discovery mode: the audit and profile collectors remain active, but Smash
bypasses its disabled and sensitive command gates, strict mode, mocks, general
egress guard, sleep cap, in-root native executable gate, and raw-socket guard.
`curl` and `wget` are the exception: they run through the same in-process
downloader as an enforced run, in an observe-only configuration — every URL,
method, and media type is admitted, the transport is pinned to the default
resolver, timeout, and size caps regardless of the policy under construction,
and `-o`/`@file` paths stay confined to the root. Discovery therefore
exercises exactly the implementation a manifest is later enforced against,
and each response's redirect hops and declared media type land in the audit
and the generated manifest — including redirect-target hosts (such as a
GitHub release's asset host) that never appear on the command line. Every
other program and network client executes directly. Their own
external-command failures retain their real status in the audit and in shell
conditions and `&&`/`||` lists. Only `set -e` termination is ignored, so a
false probe cannot select a success branch and errexit cannot truncate later
discovery. This does not make privileged operations succeed: `sudo` remains
unwrapped and never elevates. Shell syntax errors, explicit `exit` calls, and a
non-zero final status can still end the run. Use profile mode only for a trusted
script or inside separate OS-level confinement such as a container.

After review, enforce it with:

```bash
smash -manifest install.manifest.yaml install.sh
```

The script is loaded first and its bytes must match `script.sha256`; a remote
script is therefore verified after its initial fetch and before execution. A
manifest that names a different OS is also rejected. The manifest then enables
strict command gating, replaces the command allow-list,
replaces URL-prefix grants with exact host grants, and uses the same host set
for explicitly allowed Git. Other policy settings such as mocks, environment,
timeouts, request limits, and disabled commands still apply.

A manifest may also carry a `mime-types` list — the same response-body MIME
allow-list as a policy file's `network.mime-types` (bare media types or
`type/*` wildcards, checked against both the declared `Content-Type` and a
content sniff). The profiler fills it with the declared types it observed:

```yaml
mime-types:
  - application/gzip
  - application/octet-stream
```

If any observed download body arrived without a parseable `Content-Type`, the
field is omitted entirely — enforcement denies a missing `Content-Type`
whenever a list is set, so writing one would break replaying the profiled
script. Review and edit the list like the rest of the manifest. Absent,
downloads are unrestricted by type; when present it overrides any policy-file
`mime-types` for the run. `-profile` and `-manifest` are mutually exclusive.

A profile describes one observed execution path, not every path the script can
take. Arguments, environment, platform, server responses, and timing can expose
different behavior, so treat a generated manifest as review input and exercise
the variants you intend to support.

## Root handling

The root is cleared before every run. To protect against a mistyped path,
`smash` only reuses a directory when it is:

- missing;
- empty; or
- marked by a valid `.smash-root` ownership file created by an earlier run.

A file, symlink, or non-empty unmarked directory is refused instead of deleted.
Merely containing directories named `home` and `tmp` is not proof of ownership.
Cleanup is anchored to an open root handle so path or symlink replacement
cannot redirect deletion outside it.

Roots created by older versions have no marker and are intentionally refused;
remove that old sandbox directory once after confirming it contains no data to
keep.

Inside the run, `HOME` and `TMPDIR` point below the root. `PATH` starts with
`$HOME/.local/bin`, followed by common host binary directories. This is a soft
filesystem boundary; see the [security model](security-model.md).

## Policy precedence

A policy file supplies the base configuration. Only flags actually present on
the command line override it. Consequently, an absent `-strict` preserves a
policy's `strict: true`, while an explicit `-strict=false` turns it off.

```bash
smash -policy policy.yaml
smash -policy policy.yaml -strict other.sh
smash -policy policy.yaml -strict=false
```

Paths in a policy file are resolved relative to the directory from which
`smash` is run, not the policy file's directory.

## Worked example

Run the vendored Fly.io installer with the hosts used by its API and GitHub
release redirect:

```bash
smash \
  -urls https://api.fly.io/,https://github.com/superfly/,https://release-assets.githubusercontent.com \
  -audit fly-audit.yaml \
  -data 200 \
  fixtures/fly.sh --non-interactive
```

The audit stream reads as the installation's resource story: create the target
directory, fetch and write an archive, extract it, change the binary's mode,
move it into place, remove the archive, create a link, and run the installed
binary from inside the root.

If a redirect reaches a host outside `-urls`, the request is refused at that
hop and the record's `reason` identifies the rejected URL even if the installer
discarded the downloader's stderr.

The same run can be expressed as a checked-in policy; see the [policy
reference](policy.md).

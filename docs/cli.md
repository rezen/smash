# CLI reference

The `smash` CLI runs a local or remote shell script under a command, network,
filesystem-environment, and audit policy.

```text
smash [flags] SCRIPT|URL [ARGS…]
smash -policy FILE [flags] [SCRIPT [ARGS…]]
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

## Flags

| Flag | Default | Meaning |
|---|---:|---|
| `-policy FILE` | — | Read the base configuration from a YAML policy file |
| `-init-policy FILE` | — | Write a commented policy template and exit; `-` writes to stdout |
| `-urls p1,p2` | GitHub's common download hosts | Replace the URL prefixes available to in-process `curl` and `wget` |
| `-urls-github` | false | Add GitHub API, raw, codeload, objects, and release-asset hosts |
| `-git-hosts h1,h2` | GitHub, GitLab, Bitbucket | Replace the hosts Git may clone, fetch, or push to |
| `-allow a,b` | — | Add commands to the default allow-list; also permits named sensitive commands |
| `-disable a,b` | — | Deny commands outright after wrapper resolution |
| `-strict` | false | Deny every command not on the allow-list |
| `-allow-sudo` | false | Make sudo/doas credential probes succeed; commands still run without escalation |
| `-audit FILE\|-` | `-` | Write the audit stream to a file or stderr; an empty value disables it |
| `-data N` | 0 | Capture at most `N` bytes each of command stdin and stdout |
| `-root DIR` | `sandbox` | Recreated directory used for the run's `HOME`, `TMPDIR`, and leading `PATH` |

Comma-separated list flags do not trim or interpret their entries. URL entries
must include a scheme.

## Root handling

The root is cleared before every run. To protect against a mistyped path,
`smash` only reuses a directory when it is:

- missing;
- empty; or
- recognizable as a previous root containing only `home` and `tmp` directories.

A file, symlink, or directory containing anything else is refused instead of
deleted.

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

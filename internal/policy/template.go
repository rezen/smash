package policy

import (
	"fmt"
	"io"
	"os"
)

// Template is the boilerplate `smash -init-policy` writes: every knob a policy
// file has, documented, with the leaf keys commented out at their sandbox
// defaults. The section headers are live and empty (which YAML reads as null,
// and Apply as "not set"), so filling one in is a matter of deleting a `#`
// rather than remembering the nesting. Unedited, it is a policy that says
// nothing and a run under it behaves exactly as one with no policy at all —
// TestTemplateIsANoOp holds that.
const Template = `# smash policy — everything one run needs, in one file.
#
#   smash -policy this-file.yaml            # script and args come from the file
#   smash -policy this-file.yaml other.sh   # a command-line script wins
#
# Any flag given on the command line overrides the matching key here. Unknown
# keys are an error, so a typo fails the run instead of quietly dropping a rule.
# Delete the '#' on a key to set it; the value shown is the default. Relative
# paths (script, root, audit path) resolve against the directory smash runs in,
# not against this file.

# ---------------------------------------------------------------- the run ---

# The sandbox directory. It is RECREATED on every run: HOME and TMPDIR live
# inside it, and a binary that resolves inside it may execute.
#root: sandbox

# The installer to run: a local path, or an http(s):// URL fetched like
# ` + "`curl -fsS`" + ` before anything is sandboxed. A script named on the command
# line wins over this.
#script: fixtures/uv-installer.sh

# Positional parameters ($1, $2, …) for the script. Arguments given after the
# script on the command line replace this list.
#args: [--non-interactive]

# Extra environment variables, layered over the sandbox's own (HOME, TMPDIR,
# PATH, SHELL, TERM — all pointing inside root). Naming one of those replaces
# it, which is usually a way to break the sandbox rather than to configure it.
#env:
#  UV_INSTALL_DIR: /home/.local/bin

# Block every command that is neither allow-listed nor inside root. Off, an
# unlisted command runs and is flagged 'unlisted: true' in the audit log, and
# only the sensitive list is enforced.
#strict: false

# Answer sudo/doas credential probes (` + "`sudo -v`, `sudo -n -l CMD`" + `) with success,
# so an installer that gates on them proceeds. Nothing escalates: ` + "`sudo CMD`" + `
# still runs CMD confined.
#allow-sudo: false

# Run the script as sh rather than bash (also implied by a '#!/bin/sh' shebang).
#posix: false

# Wall-time bound for the whole run.
#timeout: 2m

# ------------------------------------------------------------------ audit ---

audit:
  # Where the audit trail goes: "-" is stderr, "" turns it off, anything else
  # is a file.
  #path: "-"

  # Bytes of stdin and stdout captured per command into the trail. 0 records
  # what each command touched but none of what it said.
  #data: 0

# --------------------------------------------------------------- commands ---

commands:
  # Added to the default allow-list: these run without remark. This is also the
  # only way to permit a sensitive command (sudo, python3, a host package
  # manager, …) — naming one here is a deliberate grant.
  #allow: [python3, make]

  # Blocked outright, before mocks and before the allow-list, and after
  # wrappers are unwrapped — so this catches ` + "`sudo rm`, `find -exec rm`" + ` and
  # ` + "`sh -c 'rm …'`" + ` too. A disabled command cannot be mocked back to life.
  #disable: [rm, rmdir]

  # Added to the default sensitive list: blocked even though unlisted commands
  # otherwise run.
  #sensitive: [ssh, scp]

  # Make 'allow' and 'sensitive' REPLACE the built-in lists instead of widening
  # them. 'disable' is always additive — it has no default.
  #replace: false

# ---------------------------------------------------------------- network ---

network:
  # The URL prefixes a fetch may reach; setting this replaces the default list
  # (github.com, raw.githubusercontent.com, objects.githubusercontent.com).
  # Matching is structural, not textual: scheme and host must match exactly and
  # the path must be a whole-segment prefix, so "https://example.com/pkg"
  # admits ".../pkg/v1" but not ".../pkgs" and not "example.com.evil.test".
  # Every entry needs a scheme.
  #urls:
  #  - https://api.fly.io/
  #  - https://github.com/superfly/
  #  - https://release-assets.githubusercontent.com

  # Also allow the rest of the GitHub release set (api., codeload.,
  # release-assets., …) on top of 'urls'. The CLI's -urls-github.
  #github: false

  # The hosts git may clone/fetch/push to, over any transport; a subdomain of a
  # listed host counts. Git bypasses the in-process HTTP client, so this is the
  # only gate on where it talks to. Setting it replaces the default forges.
  #git-hosts: [github.com, gitlab.com, bitbucket.org]

  # HTTP methods a downloader may use. Setting this replaces the default.
  #methods: [GET, HEAD]

  # Response body cap. A plain number is bytes; a suffix works too
  # ("200MiB", "1GB" — binary units are powers of 1024, decimal ones of 1000).
  #max-response: 200MiB

  # Per-request timeout.
  #timeout: 60s

  # Headers added to every request the sandbox makes — a broker token, say, so
  # the secret never appears in the sandboxed script itself.
  #headers:
  #  Authorization: Bearer REDACTED

# -------------------------------------------------------------- emulation ---

# Fake a target OS so a Linux-only installer can be exercised on another host:
# ` + "`uname`" + ` answers from here and the listed files appear to exist, readable.
emulation:
  #uname-os: Linux
  #uname-arch: x86_64
  #files:
  #  /etc/os-release: |
  #    ID=ubuntu
  #    VERSION_CODENAME=jammy

# ------------------------------------------------------------------ mocks ---

# Canned responses, checked in order, before the network layer and before the
# allow-list — so a mocked curl never touches the network. Each entry needs a
# 'match:' with at least one criterion; several criteria in one block must ALL
# hold. Matching happens on the real command, after wrappers are unwrapped.
#
#mocks:
#  # by exact argv
#  - match:
#      args: [uname, -s]
#    stdout: "Linux\n"
#
#  # by name AND a resource it touches (kind is url, path, host, …; the value
#  # is a glob where '*' matches anything and '?' one character)
#  - match:
#      name: [curl, wget]
#      resource: {kind: url, value: "https://releases.astral.sh/*"}
#    stdout: ""
#    exit: 0
#
#  # by a glob over the whole command line, with a failure
#  - match:
#      glob: "frobnicate *"
#    stderr: "frobnicate: boom\n"
#    exit: 3
#
#  # by argv prefix
#  - match:
#      prefix: [git, clone]
#    stdout: "Cloning into 'x'...\n"
`

// WriteTemplate writes Template to path, or to stdout when path is "-". It
// refuses to clobber an existing file: a policy is hand-edited, and silently
// replacing one with boilerplate loses work.
func WriteTemplate(path string) error {
	if path == "-" {
		_, err := io.WriteString(os.Stdout, Template)
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; remove it or choose another path", path)
		}
		return err
	}
	defer f.Close()
	if _, err := io.WriteString(f, Template); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s — fill it in, then: smash -policy %s\n", path, path)
	return f.Close()
}

package sandbox

// The command gate: the final exec handler. It decides, per command, between
// running the real program and refusing it:
//
//   - allow-listed: runs;
//   - resolving INSIDE the sandbox tree (so a freshly-installed uv can run,
//     but a host-global uv cannot): runs, flagged `in-root` — but a script
//     there is judged by the interpreter its `#!` line names, and a shell
//     script is interpreted confined rather than handed to a real shell;
//   - sensitive (privilege, host package managers, shells and interpreters
//     that would run unconfined, …): blocked unless allow-listed explicitly;
//   - anything else — the long tail of df/sw_vers/lsb_release-style probes
//     that are neither interesting nor dangerous: runs, and is flagged
//     `unlisted` in the audit trail, unless Config.Strict, which blocks it.
//
// Every network-capable command was already judged by the egress guard, and
// curl/wget were served in-process, before a command reaches this gate.

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// DefaultAllowList is a list of commands that installer
// legitimately invokes, and nothing more. It is deliberately narrower than
// command.BuiltinNames (no find/xargs/…); widen it with Set.With. curl/wget
// are absent on purpose: they are served in-process by httpMiddleware.
//
// It is the set of KNOWN commands: an allow-listed command runs without
// remark, a sensitive one is blocked, and (unless Config.Strict) anything else
// runs flagged as unlisted. Put a sensitive command here to permit it.
func DefaultAllowList() command.Set {
	return command.NewSet(
		// os / arch detection
		"uname", "getconf", "ldd", "getent", "id", "whoami", "ps",
		// temp + filesystem
		"mktemp", "mkdir", "rmdir", "rm", "mv", "cp", "ln", "chmod", "xattr", "touch", "readlink",
		// text processing
		"cat", "grep", "sed", "awk", "cut", "tr", "head", "tail", "sort", "printf",
		"echo", "dirname", "basename", "tee", "wc",
		// extract + place the binary (install is modelled as a file write, so
		// every copy it makes shows up in the audit trail)
		"tar", "unzip", "gzip", "install",
		// checksums
		"sha256sum", "sha512sum", "shasum", "openssl", "b2sum",
		// signatures: offline `gpg --import` / `gpg --verify` (terragrunt). gpg
		// is also Networked — its keyserver arguments (--keyserver,
		// --recv-keys, --search-keys, --send-keys, --fetch-keys,
		// --refresh-keys, --locate-keys, --locate-external-keys,
		// --auto-key-retrieve, --recv) are refused by the egress guard, which
		// runs before this allow-list, so granting the binary does not grant
		// the network
		"gpg", "gpg2", "gpgv",
		// source: git may run, but the egress guard holds clone/fetch/pull/push
		// to Policy.GitHosts (GitHub, GitLab, Bitbucket by default)
		"git",
		// probes: `which node`, `npm --version` (nvm's post-install checks);
		// npm's network subcommands still go through the egress guard
		"which", "npm",
		// `sudo -n true` is the idiomatic sudo probe: once sudo is unwrapped the
		// inner true/false is an external exec here, not the shell builtin
		"true", "false",
		// misc
		"sleep", "env", "date", "clear",
	)
}

// DefaultSensitiveList is the set of commands that are blocked even though
// unlisted commands run: the ones that escalate, change the host outside the
// sandbox root, or would run arbitrary code unconfined — outside every guard
// the sandbox has, the network one included. Each is a deliberate grant:
// allow-list it (`-allow NAME`, Config.Allowed) to let it run.
func DefaultSensitiveList() command.Set {
	return command.NewSet(
		// privilege: a real `sudo -v` prompts for, or uses, the user's
		// credentials (`sudo CMD` is unwrapped to CMD before it gets here and
		// never reaches sudo itself; see unwrapMiddleware and AllowSudo)
		"sudo", "doas", "su", "pkexec",
		// shells and interpreters run whatever they are given with no guard at
		// all — `sh -c` is interpreted confined by shInterpMiddleware, but
		// `sh file.sh`, `bash <(curl …)` or `python3 -c …` would not be
		"sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "csh", "tcsh",
		"python", "python2", "python3", "perl", "ruby", "node", "deno", "bun", "php", "lua", "tclsh", "osascript",
		// host package managers and installers: they write outside the root
		// (the networked ones — apt-get, brew, pip, … — are also held by the
		// egress guard; these are the offline/local-file paths)
		"dpkg", "dpkg-reconfigure", "rpm", "apk", "pacman", "emerge", "installer", "pkgutil", "softwareupdate", "snap", "flatpak",
		// system state: services, scheduling, accounts, mounts, kernel, power
		"launchctl", "systemctl", "service", "crontab", "at",
		"useradd", "usermod", "userdel", "groupadd", "chsh", "chpass", "passwd", "dscl", "visudo",
		"mount", "umount", "diskutil", "mkfs", "fdisk", "modprobe", "insmod", "sysctl", "kextload",
		"iptables", "ip6tables", "nft", "ufw", "pfctl", "defaults", "nvram", "csrutil", "spctl",
		"reboot", "shutdown", "halt", "poweroff",
		// other processes: an installer has no business signalling the host's
		"kill", "killall", "pkill",
	)
}

// gateNote is how the gate tells the audit record (recorded by the outer
// auditMiddleware) how a command got past it.
type gateNote struct {
	Unlisted bool // ran although neither allow-listed nor sensitive
	InRoot   bool // ran through the in-sandbox escape hatch
}

type gateNoteKey struct{}

// withGateNote attaches a fresh note to ctx and returns it for reading after
// the inner handlers ran.
func withGateNote(ctx context.Context) (context.Context, *gateNote) {
	n := &gateNote{}
	return context.WithValue(ctx, gateNoteKey{}, n), n
}

func gateNoteFrom(ctx context.Context) *gateNote {
	n, _ := ctx.Value(gateNoteKey{}).(*gateNote)
	return n
}

// gate is the command gate's policy: the sets it consults, the root whose
// contents may run, and how to interpret an in-root shell script confined.
type gate struct {
	root      string
	allowed   command.Set
	sensitive command.Set
	denied    command.Set
	strict    bool
	interpret scriptRunner
}

// allowListMiddleware is the command gate described at the top of this file,
// delegating to the real (os/exec-backed) default handler when a command may
// run. The three sets are consulted by command name (a path is reduced to its
// base); the escape hatch by resolved location.
func allowListMiddleware(g gate) Middleware {
	def := interp.DefaultExecHandler(2 * time.Second)
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return def(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			allowed, sensitive, strict := g.allowed, g.sensitive, g.strict
			name := filepath.Base(args[0])
			switch {
			case allowed[name]:
				return def(ctx, args) // run the real program
			case resolveInSandbox(hc, g.root, args[0]) != "":
				return g.runFromRoot(ctx, def, hc, args)
			case sensitive[name]:
				return failf(hc.Stderr, 127, "[sandbox] blocked command: %s (sensitive; allow-list it to permit)", args[0])
			case strict:
				return failf(hc.Stderr, 127, "[sandbox] blocked command: %s", args[0])
			}
			// Unlisted: not interesting enough to refuse, interesting enough to
			// flag — on stderr as the sandbox's other notices are, and on the
			// audit record so a reader can filter for what the allow-list
			// didn't anticipate.
			fmt.Fprintf(hc.Stderr, "[sandbox] unlisted command: %s\n", args[0])
			if n := gateNoteFrom(ctx); n != nil {
				n.Unlisted = true
			}
			return def(ctx, args)
		}
	}
}

// runFromRoot runs a program that resolved inside the sandbox root — the
// escape hatch that lets a freshly installed binary execute.
//
// The hatch is not a licence to run anything, because the gate reasons about
// argv[0] while the KERNEL runs whatever a `#!` line names. Writing an
// executable into the root is not an exotic capability; it is what every
// installer does. So a script installed in the root would otherwise be the
// general way past the sensitive list, past Strict and past Denied, none of
// which ever see the interpreter's name:
//
//	printf '#!/bin/bash\n…\n' > "$HOME/x"; chmod +x "$HOME/x"; "$HOME/x"
//
// A shell script never reaches here at all — shInterpMiddleware, upstream,
// interprets it confined the way it does `sh -c`. What is left is a script for
// some other interpreter, which is judged as if that interpreter had been
// invoked directly, and a real binary, which runs and is flagged InRoot so the
// hatch is never silent in the audit trail.
func (g gate) runFromRoot(ctx context.Context, def interp.ExecHandlerFunc, hc interp.HandlerContext, args []string) error {
	path := resolveInSandbox(hc, g.root, args[0])
	via, hasShebang := shebangInterpreter(path)
	name := filepath.Base(via)
	if hasShebang {
		// Denial comes first and is absolute, as it is everywhere else: an
		// interpreter the user disabled does not get to run this file, and does
		// not get interpreted in its place either.
		if g.denied[name] {
			return failf(hc.Stderr, 126, "[sandbox] disabled command: %s (%s runs it)", via, args[0])
		}
	}
	if n := gateNoteFrom(ctx); n != nil {
		n.InRoot = true
	}
	if hasShebang {
		// A shell script is not handed to a real shell: it is parsed and run in
		// a confined sub-runner, so every command inside faces the whole stack
		// again — the same treatment `sh -c` gets, for the same reason. That
		// keeps the hatch useful, since installers really do ship shell
		// wrappers, without making it a hole.
		if _, isShell := command.Lookup(name).(command.ScriptRunner); isShell && g.interpret != nil {
			return g.interpret(ctx, hc, path, args[1:], name == "sh")
		}
		switch {
		case g.allowed[name]:
		case g.sensitive[name]:
			return failf(hc.Stderr, 127, "[sandbox] blocked command: %s (%s runs it; sensitive, allow-list it to permit)", via, args[0])
		case g.strict:
			return failf(hc.Stderr, 127, "[sandbox] blocked command: %s (%s runs it)", via, args[0])
		}
	}
	return def(ctx, args)
}

// shebangInterpreter returns the interpreter a file's `#!` line names. ok is
// false for a binary, an unreadable file, or a script with no shebang (which
// the kernel refuses and the shell would run itself).
func shebangInterpreter(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	buf := make([]byte, 256)
	n, _ := io.ReadFull(f, buf)
	line, _, _ := strings.Cut(string(buf[:n]), "\n")
	rest, ok := strings.CutPrefix(line, "#!")
	if !ok {
		return "", false
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", false
	}
	// `#!/usr/bin/env python3` runs python3; env itself decides nothing.
	if filepath.Base(fields[0]) == "env" {
		for _, f := range fields[1:] {
			if !strings.HasPrefix(f, "-") && !strings.Contains(f, "=") {
				return f, true
			}
		}
		return "", false
	}
	return fields[0], true
}

// resolveInSandbox returns the absolute path a command resolves to when that
// path is within the sandbox tree, else "". Bare names are resolved against
// the RUNNER's PATH (from hc.Env), never the host process PATH — otherwise a
// host-global uv would shadow the sandbox one.
func resolveInSandbox(hc interp.HandlerContext, root, name string) string {
	var resolved string
	switch {
	case root == "":
		return ""
	case strings.ContainsRune(name, filepath.Separator):
		if filepath.IsAbs(name) {
			resolved = name
		} else {
			resolved = filepath.Join(hc.Dir, name)
		}
	default:
		if resolved = lookInSandboxPath(hc, root, name); resolved == "" {
			return ""
		}
	}
	abs, err := filepath.Abs(resolved)
	if err != nil || !withinRoot(root, abs) {
		return ""
	}
	return abs
}

// lookInSandboxPath returns the first executable match for name on the runner's
// PATH that lives inside the sandbox, or "" if none.
func lookInSandboxPath(hc interp.HandlerContext, root, name string) string {
	for _, dir := range filepath.SplitList(hc.Env.Get("PATH").String()) {
		if dir == "" {
			continue
		}
		abs, err := filepath.Abs(filepath.Join(dir, name))
		if err != nil || !withinRoot(root, abs) {
			continue
		}
		if info, err := os.Stat(abs); err == nil && !info.IsDir() {
			return abs
		}
	}
	return ""
}

// pathWithin reports whether abs is lexically inside root. It says nothing
// about symlinks; withinRoot is the one to use on a path a script chose.
func pathWithin(root, abs string) bool {
	rel, err := filepath.Rel(root, abs)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// withinRoot reports whether target is inside root once symlinks are resolved
// on both sides. The target itself need not exist — it is often a file about to
// be created — so the deepest ancestor that does exist is what gets resolved:
// a symlinked staging directory inside the root still counts as inside, and one
// pointing out of it does not. Resolving root too is what makes this work on
// macOS, where /var is a symlink to /private/var and the two spellings would
// otherwise never match.
func withinRoot(root, target string) bool {
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		realRoot = root
	}
	dir := target
	for {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			rest, err := filepath.Rel(dir, target)
			if err != nil {
				return false
			}
			return pathWithin(realRoot, filepath.Join(real, rest))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

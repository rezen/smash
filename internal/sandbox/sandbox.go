// Package sandbox runs shell scripts through an in-process interpreter
// (mvdan.cc/sh/v3) confined by a command gate (an allow-list, a sensitive
// list, and an audit trail for the unremarkable rest), an in-process network
// layer, and a scoped directory.
//
// mvdan/sh interprets only the shell *language*. Most external commands (uname,
// tar, …) are delegated to a real host binary via os/exec; selected commands
// such as those under tool/ run in-process. The sandbox wraps that exec path
// in a stack of handlers, each in its own file:
//
//	sandbox.go    Config, Run, buildRunner — wiring + execution bound
//	control.go    Disable (deny-list) and Mock (matchers → canned responses)
//	audit.go      AuditRecord, Auditor, stdin/stdout capture; OpenRecord for redirections
//	allowlist.go  the command gate: allow-list, sensitive list, unlisted-runs-audited (+ the in-sandbox escape hatch)
//	middleware.go sudo/env/timeout/… unwrapping, the sudo-probe grant, the safe `git --version` probe, and the sleep cap
//	shinterp.go   `sh -c 'SCRIPT'` parsed & re-run confined
//	internal/tool provides the portable in-process command implementations
//	network.go    Policy; curl/wget served via net/http; the egress guard
//	devnet.go     bash /dev/tcp + /dev/udp detection
//	detection.go  CallHandler shims (downloader probe, typeset compat)
//	emulate.go    opt-in target-OS emulation (fake uname + virtual files)
//	vars.go       RunVars (the resolved variable table) + Assignments (static walk)
//
// This is a SOFT boundary: mvdan/sh has no OS isolation. For a hard boundary add
// OS-level confinement (sandbox-exec / namespaces) or a container.
package sandbox

import (
	"context"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/shebang"
	"github.com/rezen/smash/internal/tool"
)

// DefaultTimeout is the wall-time bound Run applies when Config.Timeout is zero.
// It also bounds any `sh -c` recursion, since sub-runners share the context.
const DefaultTimeout = 2 * time.Minute

// Middleware wraps an exec handler. Middlewares compose outer→inner.
type Middleware = func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc

// OpenMiddleware wraps a file-open handler, the same way.
type OpenMiddleware = func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc

// Config is everything a sandboxed run needs. NewConfig fills in the defaults;
// the zero value is usable but blocks every URL and runs every command
// unlisted (set Strict, or Allowed/Sensitive, to gate them).
type Config struct {
	Root      string         // the sandbox directory; native binaries inside still require AllowInRootExecutables
	Dir       string         // initial working directory
	Env       expand.Environ // the script's environment (HOME/PATH should point inside Root)
	Network   Policy         // URL allow-list, redirect/timeout/size policy, injected headers
	Allowed   command.Set    // command names that spawn real processes without remark, sensitive or not (see DefaultAllowList)
	Sensitive command.Set    // command names blocked unless Allowed, even though unlisted commands run (see DefaultSensitiveList)
	Denied    command.Set    // command names blocked outright, even if allowed or inside Root (see Disable)
	Strict    bool           // block every command that is neither Allowed nor inside Root, instead of running it flagged unlisted
	Mocks     []*Mock        // canned responses by matcher, checked before anything runs (see Mock)
	Emulation Emulation      // optional target-OS emulation; zero value = off
	Timeout   time.Duration  // wall-time bound for one Run; zero = DefaultTimeout
	// Profile observes a script without enforcing Smash's command, mock,
	// downloader, egress, sleep, or raw-socket policy layers. External commands
	// and network clients run directly; use only with separate OS confinement or
	// a script trusted enough to execute unrestricted.
	Profile bool

	// AllowSudo answers sudo/doas credential probes (`sudo -v`, `sudo -n -l
	// mkdir`, `sudo -K`) as if the user had passwordless sudo, so an installer
	// that gates on them proceeds instead of aborting. Nothing escalates:
	// `sudo CMD` still runs CMD confined (see unwrapMiddleware). Off, a probe
	// falls to the allow-list, which blocks it.
	AllowSudo bool

	// AllowInRootExecutables permits native binaries that resolve inside Root.
	// It is deliberately off by default: native code runs outside the command,
	// filesystem and network model. Shell scripts remain interpreted confined,
	// and scripts for an explicitly allowed interpreter remain gated by it.
	AllowInRootExecutables bool

	Stdin          io.Reader
	Stdout, Stderr io.Writer // nil = discard
	// ControllingTTY, when set, is the PTY interactive external commands should
	// acquire as /dev/tty. Their ordinary stdin/stdout/stderr still come from
	// the fields above, including shell pipelines and redirections.
	ControllingTTY *os.File
	Auditor        Auditor // nil = off; else receives one AuditRecord per exec, plus one OpenRecord per redirection if it is an OpenAuditor (see TextAuditor)
	AuditData      int     // bytes of stdin/stdout captured per command into each record; 0 = none

	Args []string // positional parameters ($1…) for the script

	// Posix runs the script as `sh` rather than `bash`: the interpreter then
	// also advertises POSIXLY_CORRECT=y, as bash does in POSIX mode (which is
	// what /bin/sh is on macOS and what `curl … | sh` gives an installer).
	// Run sets it when the script's shebang names sh; set it by hand for a
	// shebang-less script that would be piped to sh.
	Posix bool

	// depth is the `sh -c`/in-root script nesting depth. It rides Config —
	// rather than a parameter — because each confined sub-runner is built
	// from a wholesale copy of the parent's Config (see shinterp.go).
	depth int
}

// NewConfig returns a Config with the default network policy, allow-list and
// sensitive list, wired to the process's stdout/stderr. Unlisted commands run
// and are audited; set Strict to block them instead.
func NewConfig(root, dir string, env expand.Environ) Config {
	return Config{
		Root: root, Dir: dir, Env: env,
		Network:   DefaultPolicy(),
		Allowed:   DefaultAllowList(),
		Sensitive: DefaultSensitiveList(),
		Timeout:   DefaultTimeout,
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
	}
}

// normalized fills the zero-value gaps so handlers never see a nil writer.
func (cfg Config) normalized() Config {
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Env == nil {
		cfg.Env = expand.ListEnviron()
	}
	return cfg
}

// Run parses src as bash and executes it under cfg, bounded by cfg.Timeout.
// name labels parse errors and diagnostics.
func Run(cfg Config, name, src string) error {
	return RunContext(context.Background(), cfg, name, src)
}

// RunContext is Run with cancellation controlled by the caller. Config.Timeout
// remains an upper bound and is layered over ctx.
func RunContext(ctx context.Context, cfg Config, name, src string) error {
	cfg, runner, prog, err := prepareRun(cfg, name, src)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	return runner.Run(ctx, prog)
}

// prepareRun is the shared front half of RunContext and RunVars: normalize
// cfg, apply the shebang POSIX rule, parse src, and assemble the runner. The
// returned Config carries the normalized Timeout the caller bounds the run
// with.
func prepareRun(cfg Config, name, src string) (Config, *interp.Runner, *syntax.File, error) {
	cfg = cfg.normalized()
	cfg.Posix = cfg.Posix || shebang.IsSh(src)
	prog, err := parseBash(name, src)
	if err != nil {
		return cfg, nil, nil, err
	}
	runner, err := buildRunner(cfg)
	if err != nil {
		return cfg, nil, nil, err
	}
	return cfg, runner, prog, nil
}

// parseBash parses a script with the bash dialect and applies the
// interpreter workarounds in fixups.go.
func parseBash(name, src string) (*syntax.File, error) {
	prog, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), name)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	rewriteSubshellReturns(prog)
	return prog, nil
}

// bashVersion is what the sandbox reports as BASH_VERSION. Installers use it
// to check they were piped to bash and not sh (nvm, brew: `[ -z
// "${BASH_VERSION}" ] && exit 1`) or to enforce a minimum (rvm sorts it
// against BASH_MIN_VERSION), so it must look like a real, current release.
const bashVersion = "5.2.37(1)-release"

// bashEnviron layers the variables bash itself defines over the caller's
// environment. Like bash, it does not export them, so exec'd commands do not
// see them; the confined `sh -c` sub-runner sets them afresh. A caller that
// sets one of these in Config.Env wins.
type bashEnviron struct {
	expand.Environ
	posix  bool   // also advertise POSIXLY_CORRECT, as bash does when run as sh
	ostype string // OSTYPE for the OS the script sees; see osType
}

var (
	bashVars = map[string]expand.Variable{
		"BASH_VERSION": {Set: true, Kind: expand.String, Str: bashVersion},
	}
	posixVars = map[string]expand.Variable{
		"POSIXLY_CORRECT": {Set: true, Kind: expand.String, Str: "y"},
	}
)

// osType is what the sandbox reports as OSTYPE, the OS name bash carries from
// the platform it was built for. Installers branch on it — mole's
// `[[ "$OSTYPE" != "darwin"* ]]` — and under `set -u` an unset OSTYPE is a
// fatal "unbound variable" rather than a branch not taken. Real bash bakes in
// its build host's release, "darwin24.4.0" or "linux-gnu"; the release digits
// go stale (a bash reporting darwin24.4.0 runs happily on a darwin25 kernel)
// and scripts match the prefix, so report the bare name and no version, just
// as the emulated `uname -r` reports a made-up release rather than a guess.
//
// unameOS is Emulation.UnameOS: with emulation on, OSTYPE follows the same
// target as the fake `uname -s`, so a script cannot see a Linux uname and a
// darwin OSTYPE at once.
func osType(unameOS string) string {
	name := strings.ToLower(unameOS)
	if name == "" {
		name = runtime.GOOS
	}
	switch name {
	case "linux":
		return "linux-gnu" // bash's spelling on glibc; still a "linux"* match
	case "windows":
		return "msys"
	}
	return name // darwin, freebsd, openbsd, netbsd, solaris, …
}

// osTypeVar is the OSTYPE entry for the maps below; bashVars cannot hold it
// because its value depends on the run's emulation.
func (e bashEnviron) osTypeVar() expand.Variable {
	return expand.Variable{Set: true, Kind: expand.String, Str: e.ostype}
}

func (e bashEnviron) builtin(name string) expand.Variable {
	if name == "OSTYPE" {
		return e.osTypeVar()
	}
	if vr, ok := bashVars[name]; ok {
		return vr
	}
	if e.posix {
		return posixVars[name]
	}
	return expand.Variable{}
}

func (e bashEnviron) Get(name string) expand.Variable {
	if vr := e.Environ.Get(name); vr.IsSet() {
		return vr
	}
	return e.builtin(name)
}

func (e bashEnviron) Each(fn func(name string, vr expand.Variable) bool) {
	e.Environ.Each(fn)
	vars := maps.Clone(bashVars)
	vars["OSTYPE"] = e.osTypeVar()
	if e.posix {
		maps.Copy(vars, posixVars)
	}
	for name, vr := range vars {
		if !e.Environ.Get(name).IsSet() && !fn(name, vr) {
			return
		}
	}
}

// execStack is the ordered exec middleware stack: the layer names (stable,
// asserted by TestExecLayerOrdering) parallel to the middlewares themselves.
type execStack struct {
	names []string
	mws   []Middleware
}

func (s *execStack) add(name string, mw Middleware) {
	s.names = append(s.names, name)
	s.mws = append(s.mws, mw)
}

// execLayers assembles the exec middleware stack, outermost first. The order
// is the enforcement contract:
//
//	unwrap       strip sudo/env/timeout/… so every later layer sees the real command
//	audit        record the real command and its true outcome, whichever layer ends it
//	deny         disabled commands die first: they cannot be mocked back to life,
//	             and -disable sudo beats AllowSudo's grant
//	sudo-grant   answer sudo/doas credential probes with success (AllowSudo, profile)
//	mock         canned responses, before the network layer and the gate
//	git-version  the inert `git --version` probe; real git stays sensitive
//	sleep-cap    cap sleeps so no script burns real wall-time
//	sh-interp    `sh -c` parsed and re-run confined, so nested commands stay visible
//	tool-*       in-process mktemp/sha256sum/base64 (portable, honoring TMPDIR)
//	uname        emulated target OS (Emulation)
//	http         curl/wget served by net/http under the URL policy, writing inside root
//	egress       every other network-capable command judged by its parsed intent
//	gate         allow-list / sensitive / in-root / unlisted — the last word
//	tty          hand interactive, terminal-facing commands the script PTY
//
// Profile mode observes without enforcing: only unwrap, audit, sudo-grant,
// sh-interp, the tools, uname and tty are installed. TestProfileModeLayers
// pins that carve-out; TestExecLayerOrdering pins the order above.
func execLayers(cfg Config) (*execStack, error) {
	enforcing := !cfg.Profile
	e := cfg.Emulation
	s := &execStack{}
	s.add("unwrap", unwrapMiddleware)
	if cfg.Auditor != nil {
		s.add("audit", auditMiddleware(cfg.Auditor, cfg.AuditData))
	}
	if enforcing && len(cfg.Denied) > 0 {
		s.add("deny", denyMiddleware(cfg.Denied))
	}
	if cfg.AllowSudo || cfg.Profile {
		s.add("sudo-grant", sudoGrantMiddleware)
	}
	if enforcing && len(cfg.Mocks) > 0 {
		s.add("mock", mockMiddleware(cfg.Mocks))
	}
	if enforcing {
		s.add("git-version", gitVersionMiddleware(resolveHostCommandPath(cfg, "git")))
		s.add("sleep-cap", sleepCapMiddleware(time.Second/5))
	}
	s.add("sh-interp", shInterpMiddleware(cfg))
	s.add("tool-mktemp", tool.Mktemp)
	s.add("tool-sha256sum", tool.SHA256Sum)
	s.add("tool-base64", tool.Base64)
	if e.UnameOS != "" {
		s.add("uname", unameMiddleware(e))
	}
	if enforcing {
		httpMW, err := httpMiddleware(cfg.Network, cfg.Root)
		if err != nil {
			return nil, err
		}
		s.add("http", httpMW)
		s.add("egress", egressGuardMiddleware(cfg.Network))
		s.add("gate", allowListMiddleware(gate{
			root: cfg.Root, allowed: cfg.Allowed, sensitive: cfg.Sensitive,
			denied: cfg.Denied, strict: cfg.Strict,
			allowInRootExecutables: cfg.AllowInRootExecutables,
			allowedPaths:           resolveAllowedPaths(cfg),
			interpret:              confinedScriptRunner(cfg),
		}))
	}
	if cfg.ControllingTTY != nil {
		s.add("tty", controllingTTYMiddleware(cfg.ControllingTTY))
	}
	return s, nil
}

// buildRunner assembles the interp.Runner: the exec stack (see execLayers for
// the layer-by-layer contract), the CallHandler shims for a couple of
// builtins, and the Open/Stat/Access handlers covering emulated files,
// /dev/tcp and the audit of the shell's own opens (redirections, `source`).
func buildRunner(cfg Config) (*interp.Runner, error) {
	e := cfg.Emulation
	stack, err := execLayers(cfg)
	if err != nil {
		return nil, err
	}
	var opens []OpenMiddleware
	if !cfg.Profile {
		opens = append(opens, netDetectOpenMiddleware(cfg.Stderr)) // inner: raw sockets
	}
	opens = append(opens, virtualOpenMiddleware(e)) // emulated files first
	if cfg.ControllingTTY != nil {
		opens = append(opens, controllingTTYOpenMiddleware(cfg.ControllingTTY))
	}
	if oa, ok := cfg.Auditor.(OpenAuditor); ok {
		opens = append(opens, auditOpenMiddleware(oa)) // outer: record every redirection/source with its outcome
	}
	open := chainOpen(interp.DefaultOpenHandler(), opens...)
	opts := []interp.RunnerOption{
		interp.Env(bashEnviron{Environ: cfg.Env, posix: cfg.Posix, ostype: osType(e.UnameOS)}),
		interp.Dir(cfg.Dir),
		interp.IgnoreErrexit(cfg.Profile),
		interp.StdIO(cfg.Stdin, cfg.Stdout, cfg.Stderr),
		interp.ExecHandlers(stack.mws...),
		interp.CallHandler(detectionCallHandler),
		interp.OpenHandler(open),
		interp.StatHandler(virtualStatHandler(e)),
		interp.AccessHandler(virtualAccessHandler(e)),
	}
	if len(cfg.Args) > 0 {
		// "--" ends option parsing, as with `set -- …`: a parameter like
		// --non-interactive must not be read as a shell option.
		opts = append(opts, interp.Params(append([]string{"--"}, cfg.Args...)...))
	}
	return interp.New(opts...)
}

// chainOpen wraps base with mws, first-listed innermost.
func chainOpen(base interp.OpenHandlerFunc, mws ...OpenMiddleware) interp.OpenHandlerFunc {
	for _, mw := range mws {
		base = mw(base)
	}
	return base
}

// Failure is the error a sandbox layer returns when it ends a command itself
// (blocked, denied, off-list URL, bad request…): the shell exit status plus
// the diagnostic it wrote to stderr. Keeping the message on the error lets the
// audit record carry the reason even when the script discards stderr
// (`curl … >/dev/null 2>&1 &` is a common installer idiom). It unwraps to
// interp.ExitStatus, so the interpreter still sees a plain exit code.
type Failure = tool.Failure

// failf reports a diagnostic to w and returns it as a Failure with the exit status.
func failf(w io.Writer, code int, format string, args ...any) error {
	return tool.Failf(w, code, format, args...)
}

// Package sandbox runs shell scripts through an in-process interpreter
// (mvdan.cc/sh/v3) confined by a command gate (an allow-list, a sensitive
// list, and an audit trail for the unremarkable rest), an in-process network
// layer, and a scoped directory.
//
// mvdan/sh interprets only the shell *language*; every external command
// (uname, tar, …) is delegated to a real host binary via os/exec. The sandbox
// wraps that exec path in a stack of handlers, each in its own file:
//
//	sandbox.go    Config, Run, buildRunner — wiring + execution bound
//	control.go    Disable (deny-list) and Mock (matchers → canned responses)
//	audit.go      AuditRecord, Auditor, stdin/stdout capture; OpenRecord for redirections
//	allowlist.go  the command gate: allow-list, sensitive list, unlisted-runs-audited (+ the in-sandbox escape hatch)
//	middleware.go sudo/env/timeout/… unwrapping + the sleep cap
//	shinterp.go   `sh -c 'SCRIPT'` parsed & re-run confined
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
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"

	"github.com/rezen/smash/internal/command"
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
	Root      string         // the sandbox directory: binaries resolving inside it may run
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

	// AllowSudo answers sudo/doas credential probes (`sudo -v`, `sudo -n -l
	// mkdir`, `sudo -K`) as if the user had passwordless sudo, so an installer
	// that gates on them proceeds instead of aborting. Nothing escalates:
	// `sudo CMD` still runs CMD confined (see unwrapMiddleware). Off, a probe
	// falls to the allow-list, which blocks it.
	AllowSudo bool

	Stdin          io.Reader
	Stdout, Stderr io.Writer // nil = discard
	Auditor        Auditor   // nil = off; else receives one AuditRecord per exec, plus one OpenRecord per redirection if it is an OpenAuditor (see TextAuditor)
	AuditData      int       // bytes of stdin/stdout captured per command into each record; 0 = none

	Args []string // positional parameters ($1…) for the script

	// Posix runs the script as `sh` rather than `bash`: the interpreter then
	// also advertises POSIXLY_CORRECT=y, as bash does in POSIX mode (which is
	// what /bin/sh is on macOS and what `curl … | sh` gives an installer).
	// Run sets it when the script's shebang names sh; set it by hand for a
	// shebang-less script that would be piped to sh.
	Posix bool

	depth int // `sh -c` nesting depth
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
	cfg = cfg.normalized()
	cfg.Posix = cfg.Posix || shebangIsSh(src)
	prog, err := parseBash(name, src)
	if err != nil {
		return err
	}
	runner, err := buildRunner(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()
	return runner.Run(ctx, prog)
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

// shebangIsSh reports whether src's first line is a shebang for sh itself
// (`#!/bin/sh`, `#!/usr/bin/env sh`, …) as opposed to bash or no shebang.
func shebangIsSh(src string) bool {
	line, _, _ := strings.Cut(src, "\n")
	if !strings.HasPrefix(line, "#!") {
		return false
	}
	fields := strings.Fields(line[2:])
	if len(fields) > 0 && filepath.Base(fields[0]) == "env" {
		fields = fields[1:]
	}
	return len(fields) > 0 && filepath.Base(fields[0]) == "sh"
}

// bashEnviron layers the variables bash itself defines over the caller's
// environment. Like bash, it does not export them, so exec'd commands do not
// see them; the confined `sh -c` sub-runner sets them afresh. A caller that
// sets one of these in Config.Env wins.
type bashEnviron struct {
	expand.Environ
	posix bool // also advertise POSIXLY_CORRECT, as bash does when run as sh
}

var (
	bashVars = map[string]expand.Variable{
		"BASH_VERSION": {Set: true, Kind: expand.String, Str: bashVersion},
	}
	posixVars = map[string]expand.Variable{
		"POSIXLY_CORRECT": {Set: true, Kind: expand.String, Str: "y"},
	}
)

func (e bashEnviron) builtin(name string) expand.Variable {
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
	vars := bashVars
	if e.posix {
		vars = maps.Clone(bashVars)
		maps.Copy(vars, posixVars)
	}
	for name, vr := range vars {
		if !e.Environ.Get(name).IsSet() && !fn(name, vr) {
			return
		}
	}
}

// buildRunner assembles the interp.Runner. Exec middlewares compose outer→inner:
// unwrap wrappers → [audit] → [deny] → [sudo grant] → [mock] → cap sleeps → confine `sh -c` and in-root shell
// scripts → [emulated uname] → serve
// curl/wget → egress guard → command gate (allow-list / sensitive / in-root / unlisted). The CallHandler shims a couple of
// builtins; the Open/Stat/Access handlers cover emulated files, /dev/tcp and
// [the audit of] the shell's own opens (redirections, `source`).
func buildRunner(cfg Config) (*interp.Runner, error) {
	e := cfg.Emulation
	mws := []Middleware{unwrapMiddleware} // strip sudo/env/timeout/… wrappers first
	if cfg.Auditor != nil {
		mws = append(mws, auditMiddleware(cfg.Auditor, cfg.AuditData)) // record the real command
	}
	if len(cfg.Denied) > 0 {
		mws = append(mws, denyMiddleware(cfg.Denied)) // disabled commands never run
	}
	if cfg.AllowSudo {
		mws = append(mws, sudoGrantMiddleware) // sudo probes succeed (after deny: -disable sudo wins)
	}
	if len(cfg.Mocks) > 0 {
		mws = append(mws, mockMiddleware(cfg.Mocks)) // canned stdout/stderr/exit by matcher
	}
	mws = append(mws,
		sleepCapMiddleware(time.Second/5), // no script burns real wall-time
		shInterpMiddleware(cfg),           // parse & confine `sh -c 'SCRIPT'`
	)
	if e.UnameOS != "" {
		mws = append(mws, unameMiddleware(e))
	}
	mws = append(mws,
		httpMiddleware(cfg.Network, cfg.Root), // curl/wget → net/http (allow-list), writing inside the root
		egressGuardMiddleware(cfg.Network),    // openssl/ssh/nc/git egress (parser-driven)
		allowListMiddleware(gate{ // the command gate
			root: cfg.Root, allowed: cfg.Allowed, sensitive: cfg.Sensitive,
			denied: cfg.Denied, strict: cfg.Strict, interpret: confinedScriptRunner(cfg),
		}),
	)
	opens := []OpenMiddleware{
		netDetectOpenMiddleware(cfg.Stderr), // inner: raw sockets
		virtualOpenMiddleware(e),            // emulated files first
	}
	if oa, ok := cfg.Auditor.(OpenAuditor); ok {
		opens = append(opens, auditOpenMiddleware(oa)) // outer: record every redirection/source with its outcome
	}
	open := chainOpen(interp.DefaultOpenHandler(), opens...)
	opts := []interp.RunnerOption{
		interp.Env(bashEnviron{cfg.Env, cfg.Posix}),
		interp.Dir(cfg.Dir),
		interp.StdIO(cfg.Stdin, cfg.Stdout, cfg.Stderr),
		interp.ExecHandlers(mws...),
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
type Failure struct {
	Code int
	Msg  string
}

func (f *Failure) Error() string { return f.Msg }
func (f *Failure) Unwrap() error { return interp.ExitStatus(f.Code) }

// failf reports a diagnostic to w and returns it as a Failure with the exit status.
func failf(w io.Writer, code int, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(w, msg)
	return &Failure{Code: code, Msg: msg}
}

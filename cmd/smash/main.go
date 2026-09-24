// Command smash runs an install script — a local path or an http(s):// URL —
// inside the in-process sandbox (internal/sandbox) under a policy given on the
// command line or in a YAML policy file, and writes an audit trail of what the
// script did.
//
// The sandbox itself lives in three packages:
//
//	internal/command  the command model — parsing, wrappers, egress indicators
//	internal/sandbox  the enforcement stack on top of mvdan.cc/sh/v3
//	internal/policy   the YAML policy file (-policy, -init-policy)
//
// This is a SOFT boundary: mvdan/sh has no OS isolation. For a hard boundary add
// OS-level confinement (sandbox-exec / namespaces) or a container. See README.
//
//go:generate sh ../../tools/sync-sh.sh
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"

	profilemanifest "github.com/rezen/smash/internal/manifest"
	"github.com/rezen/smash/internal/policy"
	"github.com/rezen/smash/internal/sandbox"
	"github.com/rezen/smash/internal/splitview"
)

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		if errors.Is(err, splitview.ErrInterrupted) {
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// runCLI runs an arbitrary script under a policy given on the command line, in
// a policy file, or both:
//
//	smash [-policy FILE] [-profile [-profile-output FILE] | -manifest FILE] [-urls p1,p2] [-urls-github] [-git-hosts h1,h2] [-dns-server IP[:PORT]] [-allow a,b] [-disable a,b] [-strict] [-allow-sudo] [-allow-in-root] [-audit FILE] [-data N] [SCRIPT [ARGS…]]
//	smash -init-policy FILE
//
// SCRIPT is a local path or an http(s):// URL; a URL is fetched once, up front,
// and then run exactly like a local file. With -policy it may instead come from
// the file's `script:` key.
//
// The two sources compose in one direction: the policy file supplies the base,
// and a flag the user actually typed overrides it. That is what makes
// `smash -policy p.yaml -strict fixtures/x.sh` mean what it reads as, and it
// is why overrides are keyed off cliFlags.set (flags SET on the command line)
// rather than off their values — -strict=false and an absent -strict have the
// same value and must not have the same effect. Each helper owns one such
// precedence decision end to end: resolveScriptArg the script+args unit,
// effectiveDNS the resolver, buildConfig the Config layering, wireAudit the
// audit sink.
func runCLI(argv []string) error {
	fl, err := parseFlags(argv)
	if err != nil {
		return err
	}
	if fl.initPolicy != "" {
		return policy.WriteTemplate(fl.initPolicy)
	}
	if fl.profile && fl.manifestPath != "" {
		return fmt.Errorf("-profile and -manifest cannot be used together")
	}
	if fl.profileOutput != "" && !fl.profile {
		return fmt.Errorf("-profile-output requires -profile")
	}

	pol := &policy.File{}
	if fl.policyPath != "" {
		p, err := policy.Load(fl.policyPath)
		if err != nil {
			return err
		}
		pol = p
	}
	scriptArg, scriptArgs, err := resolveScriptArg(pol, fl)
	if err != nil {
		return err
	}
	scriptClient, err := sandbox.NewHTTPClient(60*time.Second, effectiveDNS(pol, fl))
	if err != nil {
		return err
	}
	name, script, err := loadScript(scriptArg, scriptClient)
	if err != nil {
		return err
	}
	if fl.profile && fl.profileOutput == "" {
		fl.profileOutput = defaultManifestPath(name)
	}
	var runManifest *profilemanifest.Manifest
	if fl.manifestPath != "" {
		runManifest, err = profilemanifest.Load(fl.manifestPath)
		if err != nil {
			return err
		}
		if err := runManifest.Verify(script); err != nil {
			return fmt.Errorf("%s: %w", fl.manifestPath, err)
		}
	}

	rootPath := fl.root
	if !fl.set["root"] && pol.Root != nil {
		rootPath = *pol.Root
	}
	rootAbs, err := filepath.Abs(rootPath)
	if err != nil {
		return err
	}
	if err := resetRoot(rootAbs); err != nil {
		return err
	}
	cfg, err := buildConfig(pol, fl, rootAbs, scriptArgs, runManifest)
	if err != nil {
		return err
	}
	view, cleanup, err := wireAudit(pol, fl, &cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	var profiler *profilemanifest.Profiler
	if fl.profile {
		profiler = profilemanifest.NewProfiler(name, script, cfg.Auditor)
		cfg.Auditor = profiler
	}
	var runErr error
	if view != nil {
		runErr = view.Run(func(ctx context.Context) error {
			return sandbox.RunContext(ctx, cfg, name, script)
		})
	} else {
		runErr = sandbox.Run(cfg, name, script)
	}
	if profiler == nil {
		return runErr
	}
	writeErr := profiler.Manifest().Write(fl.profileOutput)
	if writeErr == nil {
		fmt.Fprintf(os.Stderr, "wrote profile manifest %s\n", fl.profileOutput)
	} else {
		writeErr = fmt.Errorf("writing profile manifest %s: %w", fl.profileOutput, writeErr)
	}
	return errors.Join(runErr, writeErr)
}

// cliFlags is the parsed command line. set records which flags the user
// actually TYPED: the precedence between a policy file and the flags is keyed
// off it, because a flag's zero value and an absent flag must not have the
// same effect.
type cliFlags struct {
	policyPath    string
	initPolicy    string
	profile       bool
	profileOutput string
	manifestPath  string
	urls          string
	urlsGitHub    bool
	gitHosts      string
	dnsServer     string
	allow         string
	disable       string
	strict        bool
	allowSudo     bool
	allowInRoot   bool
	audit         string
	data          int
	root          string

	scriptGiven bool     // a positional argument was present, even an empty one
	script      string   // the first positional argument
	args        []string // the positionals after it
	set         map[string]bool
}

func parseFlags(argv []string) (*cliFlags, error) {
	fl := &cliFlags{}
	fs := flag.NewFlagSet("smash", flag.ContinueOnError)
	fs.StringVar(&fl.policyPath, "policy", "", "read the run's policy from a YAML file; flags given here override it (see -init-policy)")
	fs.StringVar(&fl.initPolicy, "init-policy", "", "write a commented boilerplate policy file here (\"-\" = stdout) and exit")
	fs.BoolVar(&fl.profile, "profile", false, "run the script and write its SHA-256 plus observed commands and hosts to a manifest")
	fs.StringVar(&fl.profileOutput, "profile-output", "", "profile manifest path (default: <script>.manifest.yaml)")
	fs.StringVar(&fl.manifestPath, "manifest", "", "verify the script hash and restrict the run to commands and hosts in this manifest")
	fs.StringVar(&fl.urls, "urls", "", "comma-separated URL prefixes to allow (replaces the default)")
	fs.BoolVar(&fl.urlsGitHub, "urls-github", false, "also allow GitHub release downloads (github.com, api.github.com, raw/codeload/objects/release-assets hosts)")
	fs.StringVar(&fl.gitHosts, "git-hosts", "", "comma-separated hosts git may reach (replaces the default github.com,gitlab.com,bitbucket.org)")
	fs.StringVar(&fl.dnsServer, "dns-server", sandbox.DefaultDNSServer, "DNS resolver IP[:port] for HTTP downloads; an empty value uses the system resolver")
	fs.StringVar(&fl.allow, "allow", "", "comma-separated commands to add to the allow-list (also the way to permit a sensitive command such as sudo or python3)")
	fs.StringVar(&fl.disable, "disable", "", "comma-separated commands to disable outright")
	fs.BoolVar(&fl.strict, "strict", false, "block every command that is not allow-listed; by default an unlisted command runs and is flagged in the audit log, and only sensitive ones (sudo, shells, interpreters, host package managers, …) are blocked")
	fs.BoolVar(&fl.allowSudo, "allow-sudo", false, "answer sudo/doas credential probes (sudo -v, sudo -l CMD) with success so installers that gate on sudo proceed; sudo CMD still runs CMD confined, never escalated")
	fs.BoolVar(&fl.allowInRoot, "allow-in-root", false, "permit native executables installed inside the sandbox root; unsafe because native code runs outside in-process enforcement")
	fs.StringVar(&fl.audit, "audit", "-", "write the audit log here (\"-\" = stderr, \"\" = off)")
	fs.IntVar(&fl.data, "data", 0, "bytes of stdin/stdout to capture per command in the audit log")
	fs.StringVar(&fl.root, "root", "sandbox", "sandbox directory; it is emptied on every run, so it must be missing, empty, or carry smash's ownership marker")
	if err := fs.Parse(argv); err != nil {
		return nil, err
	}
	fl.set = map[string]bool{}
	fs.Visit(func(f *flag.Flag) { fl.set[f.Name] = true })
	if fs.NArg() > 0 {
		fl.scriptGiven = true
		fl.script, fl.args = fs.Arg(0), fs.Args()[1:]
	}
	return fl, nil
}

// resolveScriptArg picks the script and its arguments. The command line wins
// as a unit: `smash -policy p.yaml other.sh` replaces the policy's script AND
// its args, so a new script does not silently inherit arguments meant for the
// old one.
func resolveScriptArg(pol *policy.File, fl *cliFlags) (script string, args []string, err error) {
	script, args = pol.Script, pol.Args
	if fl.scriptGiven {
		script, args = fl.script, fl.args
	}
	if script == "" {
		return "", nil, fmt.Errorf("usage: smash [flags] SCRIPT|URL [ARGS…]  (or -policy FILE with a script: key, or -init-policy FILE)")
	}
	return script, args, nil
}

// effectiveDNS is the one place the DNS-resolver precedence lives: a typed
// -dns-server beats the policy file beats the default. Profile mode pins the
// default — enforcement is off, and profiling must not fail because the policy
// under construction names a broken resolver. The script fetch needs this
// value before a Config exists; a non-profile run's Config ends up with the
// same value through the ordinary policy-then-typed-flags layering in
// buildConfig.
func effectiveDNS(pol *policy.File, fl *cliFlags) string {
	switch {
	case fl.profile:
		return sandbox.DefaultDNSServer
	case fl.set["dns-server"]:
		return fl.dnsServer
	case pol.Network != nil && pol.Network.DNSServer != nil:
		return *pol.Network.DNSServer
	}
	return sandbox.DefaultDNSServer
}

// buildConfig assembles the run's Config in precedence order: sandbox
// defaults, then the policy file (pol.Apply), then each flag the user
// actually typed, then the manifest's command and host authority, and
// validation last. rootAbs has already been reset by resetRoot.
func buildConfig(pol *policy.File, fl *cliFlags, rootAbs string, scriptArgs []string, runManifest *profilemanifest.Manifest) (sandbox.Config, error) {
	home := filepath.Join(rootAbs, "home")
	tmp := filepath.Join(rootAbs, "tmp")
	// Scripts probe TERM for colour and screen control (`clear` exits 1 on a
	// dumb terminal, fatal under set -e), so pass the caller's through.
	term := os.Getenv("TERM")
	if term == "" {
		term = "dumb"
	}
	// The policy's env: pairs go last: ListEnviron sorts stably and keeps the
	// last of a duplicate name, so naming HOME there really does replace it.
	env := append([]string{
		"HOME=" + home, "TMPDIR=" + tmp, "SHELL=/bin/sh", "TERM=" + term,
		"PATH=" + filepath.Join(home, ".local", "bin") + ":/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
	}, pol.EnvPairs()...)
	cfg := sandbox.NewConfig(rootAbs, home, expand.ListEnviron(env...))
	// Keep the caller's terminal attached so interactive installers can use
	// shell reads and external command prompts.
	cfg.Stdin = os.Stdin
	cfg.Args = scriptArgs
	if err := pol.Apply(&cfg); err != nil {
		return sandbox.Config{}, err
	}

	// Flag overrides. Each is applied only if the user typed it, so a policy
	// file's value survives an untouched flag's zero default.
	set := fl.set
	if set["urls"] {
		cfg.Network.AllowedPrefixes = splitList(fl.urls)
	}
	if set["urls-github"] && fl.urlsGitHub {
		cfg.Network.AllowedPrefixes = append(cfg.Network.AllowedPrefixes, sandbox.GitHubPrefixes()...)
	}
	if set["git-hosts"] {
		cfg.Network.GitHosts = splitList(fl.gitHosts)
	}
	if set["dns-server"] {
		cfg.Network.DNSServer = fl.dnsServer
	}
	if set["allow"] {
		cfg.Allowed = cfg.Allowed.With(splitList(fl.allow)...)
	}
	if set["disable"] {
		cfg.Disable(splitList(fl.disable)...)
	}
	if set["strict"] {
		cfg.Strict = fl.strict
	}
	if set["allow-sudo"] {
		cfg.AllowSudo = fl.allowSudo
	}
	if set["allow-in-root"] {
		cfg.AllowInRootExecutables = fl.allowInRoot
	}
	if fl.profile {
		cfg.Profile = true
	}
	if runManifest != nil {
		runManifest.Apply(&cfg)
	}
	if !fl.profile {
		if err := cfg.Network.Validate(); err != nil {
			return sandbox.Config{}, err
		}
	}
	return cfg, nil
}

// wireAudit resolves where the audit stream goes — a typed -audit/-data flag
// beats the policy's audit: section — and installs the sink on cfg: "" is
// off, "-" is the split view when the terminal supports it (plain stderr when
// it does not), anything else a file. It returns the view when one was
// started, so the caller runs the script through it, and a cleanup to defer.
func wireAudit(pol *policy.File, fl *cliFlags, cfg *sandbox.Config) (*splitview.View, func(), error) {
	audit, dataBytes := fl.audit, fl.data
	if a := pol.Audit; a != nil {
		if !fl.set["audit"] && a.Path != nil {
			audit = *a.Path
		}
		if !fl.set["data"] && a.Data != nil {
			dataBytes = *a.Data
		}
	}
	cfg.AuditData = dataBytes
	cleanup := func() {}
	switch audit {
	case "":
	case "-":
		view, ok, err := splitview.Start(os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			return nil, cleanup, err
		}
		if !ok {
			cfg.Auditor = sandbox.TextAuditor(os.Stderr, sandbox.ShortPaths(*cfg))
			break
		}
		cfg.Stdin, cfg.Stdout, cfg.Stderr = view.Stdio()
		cfg.ControllingTTY = view.TTY()
		cfg.Auditor = sandbox.TextAuditor(view.EventWriter(), sandbox.ShortPaths(*cfg))
		return view, func() { view.Close() }, nil
	default:
		f, err := os.Create(audit)
		if err != nil {
			return nil, cleanup, err
		}
		cfg.Auditor = sandbox.TextAuditor(f, sandbox.ShortPaths(*cfg))
		cleanup = func() { f.Close() }
	}
	return nil, cleanup, nil
}

func defaultManifestPath(scriptName string) string {
	base := filepath.Base(scriptName)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if name == "" {
		name = "script"
	}
	return name + ".manifest.yaml"
}

// splitList splits a comma-separated flag value, treating "" as the empty list
// rather than as one empty entry.
func splitList(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// rootMarker is the ownership proof resetRoot requires before deleting
// anything from a non-empty directory. Directory names such as home and tmp
// are not proof: an unrelated directory may legitimately contain both.
const (
	rootMarker        = ".smash-root"
	rootMarkerContent = "smash sandbox root v1\n"
)

// resetRoot empties a sandbox directory and recreates home and tmp inside it.
// A missing or empty directory is claimed by writing rootMarker. Every later
// reuse requires that exact marker; a non-empty unmarked directory is refused.
//
// os.Root anchors all inspection and deletion to the directory handle. Even
// if the path is renamed while cleanup is in progress, RemoveAll cannot escape
// into a replacement directory or through an outward-pointing symlink.
func resetRoot(root string) error {
	fi, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(root, 0o755); err != nil {
			return err
		}
		fi, err = os.Lstat(root)
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() { // a file or a symlink: never ours
		return fmt.Errorf("root %s exists and is not a directory", root)
	}

	r, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer r.Close()
	opened, err := r.Stat(".")
	if err != nil || !os.SameFile(fi, opened) {
		return fmt.Errorf("root %s changed while it was being opened; refusing to clear it", root)
	}
	dir, err := r.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	dir.Close()
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		f, err := r.OpenFile(rootMarker, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("claiming root %s: %w", root, err)
		}
		if _, err := io.WriteString(f, rootMarkerContent); err != nil {
			f.Close()
			return fmt.Errorf("claiming root %s: %w", root, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("claiming root %s: %w", root, err)
		}
	} else {
		markerInfo, statErr := r.Lstat(rootMarker)
		marker, err := r.ReadFile(rootMarker)
		if statErr != nil || !markerInfo.Mode().IsRegular() || err != nil || string(marker) != rootMarkerContent {
			return fmt.Errorf("root %s is non-empty and has no valid %s marker; choose an empty directory or remove it yourself", root, rootMarker)
		}
	}

	for _, e := range entries {
		if e.Name() == rootMarker {
			continue
		}
		if err := r.RemoveAll(e.Name()); err != nil {
			return fmt.Errorf("clearing %s from root %s: %w", e.Name(), root, err)
		}
	}
	for _, d := range []string{"home", "tmp"} {
		if err := r.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// maxScriptBytes bounds a remote installer's size; real ones are tens of KiB.
const maxScriptBytes = 16 << 20

// loadScript reads the installer named on the command line. An http(s):// URL
// is fetched the way `curl -fsS URL` would: silently, following redirects,
// failing without a body on any 4xx/5xx, and reporting transport errors. The
// fetch is the user's explicit request, so it is not subject to the sandbox's
// URL allow-list — only the script's own downloads are. Anything else is a
// local path. It returns the display name used in the audit log and the source.
func loadScript(arg string, client *http.Client) (name, src string, err error) {
	u, perr := url.Parse(arg)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		b, err := os.ReadFile(arg)
		if err != nil {
			return "", "", err
		}
		return filepath.Base(arg), string(b), nil
	}
	resp, err := client.Get(arg)
	if err != nil {
		return "", "", fmt.Errorf("fetch %s: %w", arg, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 { // curl -f
		return "", "", fmt.Errorf("fetch %s: The requested URL returned error: %d", arg, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxScriptBytes+1))
	if err != nil {
		return "", "", fmt.Errorf("fetch %s: %w", arg, err)
	}
	if len(b) > maxScriptBytes {
		return "", "", fmt.Errorf("fetch %s: script exceeds %d bytes", arg, maxScriptBytes)
	}
	name = path.Base(u.Path)
	if name == "" || name == "." || name == "/" {
		name = u.Host
	}
	return name, string(b), nil
}

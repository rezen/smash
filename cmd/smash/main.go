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

	"github.com/rezen/smash/internal/policy"
	"github.com/rezen/smash/internal/sandbox"
)

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// runCLI runs an arbitrary script under a policy given on the command line, in
// a policy file, or both:
//
//	smash [-policy FILE] [-urls p1,p2] [-urls-github] [-git-hosts h1,h2] [-allow a,b] [-disable a,b] [-strict] [-allow-sudo] [-audit FILE] [-data N] [SCRIPT [ARGS…]]
//	smash -init-policy FILE
//
// SCRIPT is a local path or an http(s):// URL; a URL is fetched once, up front,
// and then run exactly like a local file. With -policy it may instead come from
// the file's `script:` key.
//
// The two sources compose in one direction: the policy file supplies the base,
// and a flag the user actually typed overrides it. That is what makes
// `smash -policy p.yaml -strict fixtures/x.sh` mean what it reads as, and it
// is why the overrides below are keyed off fs.Visit (flags SET on the command
// line) rather than off their values — -strict=false and an absent -strict have
// the same value and must not have the same effect.
func runCLI(argv []string) error {
	fs := flag.NewFlagSet("smash", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "read the run's policy from a YAML file; flags given here override it (see -init-policy)")
	initPolicy := fs.String("init-policy", "", "write a commented boilerplate policy file here (\"-\" = stdout) and exit")
	urls := fs.String("urls", "", "comma-separated URL prefixes to allow (replaces the default)")
	urlsGitHub := fs.Bool("urls-github", false, "also allow GitHub release downloads (github.com, api.github.com, raw/codeload/objects/release-assets hosts)")
	gitHosts := fs.String("git-hosts", "", "comma-separated hosts git may reach (replaces the default github.com,gitlab.com,bitbucket.org)")
	allow := fs.String("allow", "", "comma-separated commands to add to the allow-list (also the way to permit a sensitive command such as sudo or python3)")
	disable := fs.String("disable", "", "comma-separated commands to disable outright")
	strict := fs.Bool("strict", false, "block every command that is not allow-listed; by default an unlisted command runs and is flagged in the audit log, and only sensitive ones (sudo, shells, interpreters, host package managers, …) are blocked")
	allowSudo := fs.Bool("allow-sudo", false, "answer sudo/doas credential probes (sudo -v, sudo -l CMD) with success so installers that gate on sudo proceed; sudo CMD still runs CMD confined, never escalated")
	auditPath := fs.String("audit", "-", "write the audit log here (\"-\" = stderr, \"\" = off)")
	data := fs.Int("data", 0, "bytes of stdin/stdout to capture per command in the audit log")
	root := fs.String("root", "sandbox", "sandbox directory; it is emptied on every run, so it must be missing, empty, or a previous sandbox")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *initPolicy != "" {
		return policy.WriteTemplate(*initPolicy)
	}
	set := map[string]bool{} // flags the user actually typed
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	pol := &policy.File{}
	if *policyPath != "" {
		p, err := policy.Load(*policyPath)
		if err != nil {
			return err
		}
		pol = p
	}

	// The script and its arguments: the command line wins as a unit, so
	// `smash -policy p.yaml other.sh` does not silently inherit p.yaml's args.
	scriptArg, scriptArgs := pol.Script, pol.Args
	if fs.NArg() > 0 {
		scriptArg, scriptArgs = fs.Arg(0), fs.Args()[1:]
	}
	if scriptArg == "" {
		return fmt.Errorf("usage: smash [flags] SCRIPT|URL [ARGS…]  (or -policy FILE with a script: key, or -init-policy FILE)")
	}
	name, script, err := loadScript(scriptArg)
	if err != nil {
		return err
	}

	rootPath := *root
	if !set["root"] && pol.Root != nil {
		rootPath = *pol.Root
	}
	rootAbs, err := filepath.Abs(rootPath)
	if err != nil {
		return err
	}
	home := filepath.Join(rootAbs, "home")
	tmp := filepath.Join(rootAbs, "tmp")
	if err := resetRoot(rootAbs, home, tmp); err != nil {
		return err
	}
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
	cfg.Args = scriptArgs
	if err := pol.Apply(&cfg); err != nil {
		return err
	}

	// Flag overrides. Each is applied only if the user typed it, so a policy
	// file's value survives an untouched flag's zero default.
	if set["urls"] {
		cfg.Network.AllowedPrefixes = splitList(*urls)
	}
	if set["urls-github"] && *urlsGitHub {
		cfg.Network.AllowedPrefixes = append(cfg.Network.AllowedPrefixes, sandbox.GitHubPrefixes()...)
	}
	if set["git-hosts"] {
		cfg.Network.GitHosts = splitList(*gitHosts)
	}
	if set["allow"] {
		cfg.Allowed = cfg.Allowed.With(splitList(*allow)...)
	}
	if set["disable"] {
		cfg.Disable(splitList(*disable)...)
	}
	if set["strict"] {
		cfg.Strict = *strict
	}
	if set["allow-sudo"] {
		cfg.AllowSudo = *allowSudo
	}
	if err := cfg.Network.Validate(); err != nil {
		return err
	}

	audit, dataBytes := *auditPath, *data
	if a := pol.Audit; a != nil {
		if !set["audit"] && a.Path != nil {
			audit = *a.Path
		}
		if !set["data"] && a.Data != nil {
			dataBytes = *a.Data
		}
	}
	switch audit {
	case "":
	case "-":
		cfg.Auditor = sandbox.TextAuditor(os.Stderr, sandbox.ShortPaths(cfg))
	default:
		f, err := os.Create(audit)
		if err != nil {
			return err
		}
		defer f.Close()
		cfg.Auditor = sandbox.TextAuditor(f, sandbox.ShortPaths(cfg))
	}
	cfg.AuditData = dataBytes
	return sandbox.Run(cfg, name, script)
}

// splitList splits a comma-separated flag value, treating "" as the empty list
// rather than as one empty entry.
func splitList(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

// resetRoot empties the sandbox directory and recreates home and tmp inside it.
//
// The directory is deleted, so it is checked first. A mistyped -root (or a
// policy file's root:) would otherwise recursively delete whatever the path
// happens to name — a source tree, a home directory — with no confirmation and
// no way back. Only an empty directory, a missing one, or one this tool
// evidently created before is emptied; anything else is refused and named, and
// the user can delete it themselves if that is what they meant.
func resetRoot(root, home, tmp string) error {
	switch reusable, err := reusableRoot(root); {
	case err != nil:
		return err
	case !reusable:
		return fmt.Errorf("root %s already exists and is not a previous sandbox; pass -root DIR or remove it first", root)
	}
	if err := os.RemoveAll(root); err != nil {
		return fmt.Errorf("clearing root %s: %w", root, err)
	}
	for _, d := range []string{home, tmp} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// reusableRoot reports whether root may be deleted: it does not exist, it is
// an empty directory, or it holds nothing but the home and tmp a previous run
// created. A file, a symlink, or a directory with anything else in it is not.
func reusableRoot(root string) (bool, error) {
	fi, err := os.Lstat(root)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() { // a file or a symlink: never ours
		return false, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if !e.IsDir() || (e.Name() != "home" && e.Name() != "tmp") {
			return false, nil
		}
	}
	return true, nil
}

// maxScriptBytes bounds a remote installer's size; real ones are tens of KiB.
const maxScriptBytes = 16 << 20

// loadScript reads the installer named on the command line. An http(s):// URL
// is fetched the way `curl -fsS URL` would: silently, following redirects,
// failing without a body on any 4xx/5xx, and reporting transport errors. The
// fetch is the user's explicit request, so it is not subject to the sandbox's
// URL allow-list — only the script's own downloads are. Anything else is a
// local path. It returns the display name used in the audit log and the source.
func loadScript(arg string) (name, src string, err error) {
	u, perr := url.Parse(arg)
	if perr != nil || (u.Scheme != "http" && u.Scheme != "https") {
		b, err := os.ReadFile(arg)
		if err != nil {
			return "", "", err
		}
		return filepath.Base(arg), string(b), nil
	}
	client := &http.Client{Timeout: 60 * time.Second}
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

package command

// Package managers. Install scripts lean on them (get-docker: apt-get, yum,
// zypper; rvm: apt/brew/…), and almost every one reaches the network for the
// subcommands that matter. They are neither Builtins (not offline) nor plain
// NetTools (the resource is a package, and only some subcommands egress), so
// PackageManager is its own data-driven type: Networked for the egress guard,
// Describer for the audit log ("apt-get: install package docker-ce").

import "strings"

// PackageManager is a data-driven package-manager command.
type PackageManager struct {
	Aliases      []string
	Spec         Spec
	Network      Set      // subcommands that reach the network (install, update, …)
	NetworkFlags []string // for flag-driven managers: pacman -S, rpm -i URL
	Always       bool     // every invocation with a subcommand or operand fetches (cpan)
}

func (m PackageManager) Names() []string                { return m.Aliases }
func (m PackageManager) Parse(a []string) ParsedCommand { return m.Spec.Parse(a) }

// Egress: a URL operand always egresses (pip install https://…, rpm -i
// http://…); otherwise a network subcommand or network flag does.
func (m PackageManager) Egress(p ParsedCommand) (string, bool) {
	for _, o := range p.Operands {
		if strings.Contains(o, "://") {
			return o, true
		}
	}
	if m.Network[p.Subcommand] {
		return p.Subcommand, true
	}
	for _, fl := range m.NetworkFlags {
		if p.HasFlag(fl) {
			return fl, true
		}
	}
	if m.Always {
		if p.Subcommand != "" {
			return p.Subcommand, true
		}
		if len(p.Operands) > 0 {
			return p.Operands[0], true
		}
	}
	return "", false
}

// Resources: each operand is a package (or a URL) acted on by the subcommand;
// with no operands the action applies to the package set as a whole
// (`apt-get update`, `pacman -Syu`).
func (m PackageManager) Resources(p ParsedCommand) []Resource {
	action := p.Subcommand
	if action == "" {
		for _, fl := range m.NetworkFlags {
			if p.HasFlag(fl) {
				action = fl
				break
			}
		}
	}
	if action == "" {
		action = "manage"
	}
	if len(p.Operands) == 0 {
		return []Resource{{Kind: "packages", Action: action}}
	}
	rs := make([]Resource, 0, len(p.Operands))
	for _, o := range p.Operands {
		kind := "package"
		if strings.Contains(o, "://") {
			kind = "url"
		} else if strings.ContainsAny(o, "/") || strings.HasSuffix(o, ".deb") || strings.HasSuffix(o, ".rpm") || strings.HasSuffix(o, ".apk") {
			kind = "path"
		}
		rs = append(rs, Resource{Kind: kind, Action: action, Value: o})
	}
	return rs
}

// pm builds a subcommand-driven PackageManager.
func pm(names []string, network Set, valueFlags ...string) PackageManager {
	return PackageManager{Aliases: names, Spec: Spec{Subcommand: true, ValueFlags: NewSet(valueFlags...)}, Network: network}
}

var (
	pmInstall = NewSet("install", "reinstall", "upgrade", "update", "dist-upgrade", "full-upgrade",
		"download", "search", "fetch", "sync", "add", "pull", "refresh", "check-update", "makecache")
)

var packageManagers = []Command{
	// Debian/Ubuntu
	pm(names("apt", "apt-get", "aptitude"), pmInstall.With("source", "build-dep", "changelog", "edit-sources"),
		"-o", "--option", "-t", "--target-release", "-c", "--config-file"),
	pm(names("apt-cache"), NewSet(), "-o", "-c"),                                                                // local index queries
	PackageManager{Aliases: names("dpkg"), Spec: Spec{ValueFlags: NewSet("--root", "--admindir", "--instdir")}}, // local .deb only; URLs impossible
	// RPM world
	pm(names("yum", "dnf", "microdnf", "tdnf"), pmInstall.With("groupinstall", "group", "localinstall", "distro-sync", "repolist", "info", "list", "provides", "whatprovides", "module"),
		"-c", "--config", "--enablerepo", "--disablerepo", "--releasever", "--setopt", "--installroot"),
	pm(names("zypper"), pmInstall.With("in", "up", "dup", "se", "ref", "patch", "source-install", "addrepo", "ar", "modifyrepo"),
		"-c", "--config", "--root", "-R"),
	PackageManager{Aliases: names("rpm"), Spec: Spec{ClusterShort: true, ValueFlags: NewSet("--root", "--prefix", "--dbpath")}}, // egresses only on a URL operand
	// Alpine, Arch, Gentoo, Void
	pm(names("apk"), pmInstall.With("del", "cache", "policy", "list", "info"), "-X", "--repository", "--root", "-p", "--cache-dir", "--keys-dir"),
	PackageManager{Aliases: names("pacman", "yay", "paru"), Spec: Spec{ClusterShort: true, ValueFlags: NewSet("-r", "--root", "-b", "--dbpath", "--cachedir", "--config")},
		NetworkFlags: []string{"-S", "--sync", "-U", "--upgrade", "-F", "--files"}},
	pm(names("emerge"), NewSet("--sync", "--fetchonly"), "--root", "--config-root", "-j"),
	pm(names("xbps-install"), NewSet(), "-R", "--repository", "-r", "--rootdir"),
	// macOS / Nix / universal
	pm(names("brew"), pmInstall.With("tap", "cask", "outdated", "bundle", "info"), "--cask"),
	pm(names("port"), pmInstall.With("selfupdate", "outdated", "info", "variants")),
	pm(names("nix", "nix-env", "nix-shell", "nix-build", "nix-channel"), pmInstall.With("profile", "shell", "run", "develop", "build", "flake", "--install", "-i", "--upgrade", "-u"), "-f", "--file", "-A", "--attr", "-p", "--packages", "-I"),
	pm(names("snap"), pmInstall.With("find", "refresh", "info", "connect")),
	pm(names("flatpak"), pmInstall.With("remote-add", "remote-ls", "run", "repair", "info"), "--installation", "--user", "--system"),
	pm(names("conda", "mamba", "micromamba"), pmInstall.With("create", "env", "info"), "-n", "--name", "-p", "--prefix", "-c", "--channel", "-f", "--file"),
	// language ecosystems
	pm(names("pip", "pip3", "pipx", "uv", "poetry", "pipenv"), pmInstall.With("wheel", "python", "tool", "lock", "run", "venv", "self", "cache", "index"),
		"-r", "--requirement", "-i", "--index-url", "--extra-index-url", "-e", "--editable", "-c", "--constraint", "-t", "--target", "-p", "--python", "--find-links", "-f"),
	pm(names("npm", "npx", "yarn", "pnpm", "bun"), pmInstall.With("i", "ci", "exec", "dlx", "create", "publish", "view", "info", "outdated", "audit", "cache", "ping", "x"),
		"--registry", "--prefix", "-C", "--cwd", "--filter", "-w", "--workspace"),
	pm(names("gem"), pmInstall.With("push", "yank", "outdated", "query", "list")),
	pm(names("bundle", "bundler"), pmInstall.With("exec", "outdated", "lock", "package"), "--gemfile", "--path", "-j", "--jobs"),
	pm(names("cargo"), pmInstall.With("build", "run", "test", "check", "publish", "vendor", "generate-lockfile", "clippy", "doc"), "--manifest-path", "--target-dir", "-p", "--package", "--features", "-j"),
	pm(names("go"), NewSet("get", "install", "mod", "build", "run", "test", "list", "vet", "generate"), "-C", "-o", "-p", "-tags", "-ldflags", "-gcflags", "-mod", "-modfile", "-overlay"),
	pm(names("composer"), pmInstall.With("require", "create-project", "outdated", "show"), "-d", "--working-dir"),
	PackageManager{Aliases: names("cpan", "cpanm", "cpanminus"), Always: true,
		Spec: Spec{ValueFlags: NewSet("-l", "--local-lib", "-L", "--local-lib-contained", "--mirror")}},
}

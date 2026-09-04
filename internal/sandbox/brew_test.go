package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBrewInstallerContained runs Homebrew's installer (fixtures/brew-install.sh)
// under Linux/x86_64 emulation, where it targets /home/linuxbrew/.linuxbrew —
// a prefix that needs root. The script clears its preflight (bash check,
// non-interactive mode, OS/arch detection, the Ruby and glibc probes — ruby is
// mocked absent and `ldd --version` mocked new enough) and then asks for sudo.
// The sandbox never grants it: `/usr/bin/sudo -n -l mkdir` is stopped by the
// allow-list, `have_sudo_access` fails, and brew aborts on its own permission
// check before a single `install`/`chown`/`git` runs. No sudo prompt, no
// privileged writes, nothing under /home/linuxbrew.
//
// On macOS the script would target /opt/homebrew (a real, user-writable path
// on a Homebrew host) and, once the sudo probe fails, run its chowns and
// `git init` directly — which is why this test always emulates Linux.
func TestBrewInstallerContained(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root brew skips the sudo probe and would install for real")
	}
	var recs []AuditRecord
	var root string
	out, er, err := runConfined(t, fixture(t, "brew-install.sh"),
		withHome(t, "SHELL=/bin/bash", "NONINTERACTIVE=1", "USER=tester"),
		collectAudit(&recs),
		func(c *Config) {
			root = c.Root
			c.Emulation = Emulation{UnameOS: "Linux", UnameArch: "x86_64"}
			c.Mock(MatchName("ruby"), "", "", 1)
			c.Mock(MatchName("ldd"), "ldd (Ubuntu GLIBC 2.35-0ubuntu3) 2.35\n", "", 0)
			// Belt and braces: even if a host let the permission check pass,
			// the privileged steps could not run.
			c.Disable("install", "chown", "chgrp")
		})
	combined := out + er
	if err == nil {
		t.Fatalf("expected brew to be contained; got success\n%s", combined)
	}
	for _, want := range []string{
		"Running in non-interactive mode",
		"Checking for `sudo` access",
		"blocked command: /usr/bin/sudo",
		`Insufficient permissions to install Homebrew to "/home/linuxbrew/.linuxbrew"`,
	} {
		if !strings.Contains(combined, want) {
			t.Errorf("output missing %q:\n%s", want, combined)
		}
	}
	for _, unwanted := range []string{"only supported on macOS and Linux", "Homebrew requires Ruby", "disabled command", "This script will install"} {
		if strings.Contains(combined, unwanted) {
			t.Errorf("brew got further (or less far) than the sudo check: found %q:\n%s", unwanted, combined)
		}
	}
	if _, statErr := os.Stat("/home/linuxbrew"); statErr == nil {
		t.Error("/home/linuxbrew exists — the installer was not contained")
	}
	if changes := auditFileChanges(recs); len(changes) > 0 {
		t.Errorf("expected no file changes before the sudo check; got %v", changes)
	}
	assertConfined(t, recs, root)
}

// TestBrewInstallerSudoGranted: the same run with AllowSudo. The sandbox
// answers `/usr/bin/sudo -n -l mkdir` with success, so have_sudo_access passes
// and brew announces its install plan — then its first privileged step,
// `/usr/bin/sudo /usr/bin/install -d … /home/linuxbrew/.linuxbrew`, is
// unwrapped to a confined `install` and stopped by the disable list. The
// grant exposes what the installer would do with root; it never escalates.
func TestBrewInstallerSudoGranted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root brew skips the sudo probe and would install for real")
	}
	var recs []AuditRecord
	var root string
	out, er, err := runConfined(t, fixture(t, "brew-install.sh"),
		withHome(t, "SHELL=/bin/bash", "NONINTERACTIVE=1", "USER=tester"),
		collectAudit(&recs),
		func(c *Config) {
			root = c.Root
			c.AllowSudo = true
			c.Emulation = Emulation{UnameOS: "Linux", UnameArch: "x86_64"}
			c.Mock(MatchName("ruby"), "", "", 1)
			c.Mock(MatchName("ldd"), "ldd (Ubuntu GLIBC 2.35-0ubuntu3) 2.35\n", "", 0)
			c.Disable("install", "chown", "chgrp")
		})
	combined := out + er
	if err == nil {
		t.Fatalf("expected brew to be contained at its first privileged step; got success\n%s", combined)
	}
	// The probe's stderr goes to /dev/null in the script, so look for the
	// grant in the audit trail: a sudo record that succeeded.
	var granted bool
	for _, r := range recs {
		if r.Name == "sudo" && r.Exit == nil {
			granted = true
		}
	}
	if !granted {
		t.Errorf("expected an audited, successful sudo probe:\n%s", combined)
	}
	for _, want := range []string{
		"This script will install",
		"/usr/bin/sudo /usr/bin/install -d",
		"unwrapped sudo → /usr/bin/install",
		"disabled command: /usr/bin/install",
	} {
		if !strings.Contains(combined, want) {
			t.Errorf("output missing %q:\n%s", want, combined)
		}
	}
	if strings.Contains(combined, "Insufficient permissions") {
		t.Errorf("the sudo grant should have cleared brew's permission check:\n%s", combined)
	}
	if _, statErr := os.Stat("/home/linuxbrew"); statErr == nil {
		t.Error("/home/linuxbrew exists — the installer was not contained")
	}
	// The audit shows the privileged write brew attempted — and that it failed.
	// That record is the only change outside the root; nothing else escaped.
	var attempted bool
	for _, r := range recs {
		for _, c := range r.Files {
			if strings.HasPrefix(c.Path, root+string(filepath.Separator)) || !filepath.IsAbs(c.Path) {
				continue
			}
			if c.Path != "/home/linuxbrew/.linuxbrew" || r.Exit == nil {
				t.Errorf("%s changed a path outside the sandbox root: %s (exit %v)", r.Name, c.Path, r.Exit)
			}
			attempted = true
		}
	}
	if !attempted {
		t.Error("expected the audit to record the stopped install of /home/linuxbrew/.linuxbrew")
	}
}

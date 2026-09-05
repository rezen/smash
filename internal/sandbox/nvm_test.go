package sandbox

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// nvmStub is the "nvm.sh" the mocked download serves: enough for the installer
// to source it and drive `nvm install` / `nvm_version` afterwards.
const nvmStub = "# fake nvm.sh\nnvm() { echo \"fake nvm $*\"; }\nnvm_version() { echo v22.0.0; }\n"

// TestNVMScriptInstallAuditTrail runs nvm's installer (fixtures/nvm.sh) in its
// script mode with NO network: the three raw.githubusercontent.com downloads
// (nvm.sh, nvm-exec, bash_completion — backgrounded with `&`) are mocked. The
// installer then appends its source lines to the profile, SOURCES the
// downloaded nvm.sh inside the interpreter, probes the host npm for global
// modules, and installs the requested Node through the sourced `nvm`.
//
// (The installer waits on its downloads with `jobs -p`, which mvdan/sh does not
// implement; the mocks finish synchronously, so the install still completes.)
func TestNVMScriptInstallAuditTrail(t *testing.T) {
	var recs []AuditRecord
	var download *Mock
	var cfg Config
	out, er, err := runConfined(t, fixture(t, "nvm.sh"), collectAudit(&recs), func(c *Config) {
		home := filepath.Join(c.Root, "home")
		fakeBin := filepath.Join(home, "fakebin")
		if err := os.MkdirAll(fakeBin, 0o755); err != nil {
			t.Fatal(err)
		}
		// A host "npm" with one global module, so nvm's global-modules check
		// is exercised deterministically (it lives inside the root, so the
		// allow-list's escape hatch would run it even without the grant).
		npm := "#!/bin/sh\ncase \"$1\" in --version) echo 10.8.0 ;; list) printf '%s\\n' /usr/local/lib '├── npm@10.8.0' '└── yarn@1.22.22' ;; esac\n"
		if err := os.WriteFile(filepath.Join(fakeBin, "npm"), []byte(npm), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".bashrc"), []byte("# rc\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		withHome(t, "SHELL=/bin/bash", "METHOD=script", "NODE_VERSION=22")(c)
		c.Env = envWith(c.Env, "PATH="+fakeBin+":"+strings.TrimPrefix(hostPath, "PATH="))
		download = c.MockFunc(MatchName("curl").And(MatchResource("url", "https://raw.githubusercontent.com/nvm-sh/nvm/*")),
			func(p command.ParsedCommand) (string, string, int) {
				cp := p.TypedParams().(command.CurlParams)
				body := "# fake " + path.Base(cp.URL) + "\n"
				if path.Base(cp.URL) == "nvm.sh" {
					body = nvmStub
				}
				if err := os.WriteFile(cp.Output, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				return "", "", 0
			})
		// nvm's macOS check runs `xcode-select -p`; answer as if the CLT are
		// installed rather than let the allow-list block it.
		c.Mock(MatchName("xcode-select"), "/Library/Developer/CommandLineTools\n", "", 0)
		cfg = *c
	})
	if err != nil {
		t.Fatalf("installer failed: %v\nstdout=%s\nstderr=%s", err, out, er)
	}
	for _, want := range []string{
		"=> Downloading nvm as script to '" + filepath.Join(cfg.Dir, ".nvm") + "'",
		"=> Appending nvm source string to " + filepath.Join(cfg.Dir, ".bashrc"),
		"=> Appending bash_completion source string to",
		"=> You currently have modules installed globally with `npm`",
		"└── yarn@1.22.22",
		"fake nvm install 22",
		"=> Node.js version 22 has been successfully installed",
		"=> Close and reopen your terminal to start using nvm",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s\n%s", want, out, er)
		}
	}

	// Exactly the three script-mode fetches, all pinned to the version the
	// installer embeds.
	var urls []string
	for _, p := range download.Calls() {
		cp := p.TypedParams().(command.CurlParams)
		if !cp.FailFast || cp.Output == "" {
			t.Errorf("download curl params: %+v", cp)
		}
		urls = append(urls, cp.URL)
	}
	sort.Strings(urls)
	want := []string{
		"https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/bash_completion",
		"https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/nvm-exec",
		"https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.7/nvm.sh",
	}
	if strings.Join(urls, "\n") != strings.Join(want, "\n") {
		t.Errorf("fetched URLs:\n%s\nwant:\n%s", strings.Join(urls, "\n"), strings.Join(want, "\n"))
	}

	nvmDir := filepath.Join(cfg.Dir, ".nvm")
	if fi, err := os.Stat(filepath.Join(nvmDir, "nvm-exec")); err != nil || fi.Mode()&0o111 == 0 {
		t.Errorf("nvm-exec not installed executable: %v %v", fi, err)
	}
	rc, _ := os.ReadFile(filepath.Join(cfg.Dir, ".bashrc"))
	if !strings.Contains(string(rc), `export NVM_DIR="$HOME/.nvm"`) || !strings.Contains(string(rc), "bash_completion") {
		t.Errorf(".bashrc was not updated:\n%s", rc)
	}
	// Downloads written, nvm-exec chmod'ed, the profile appended; nothing
	// outside the root.
	assertChanges(t, recs, "write nvm.sh", "write nvm-exec", "write bash_completion", "mode nvm-exec")
	assertConfined(t, recs, cfg.Root)
}

// TestNVMGitInstallHeldByEgressGuard: with git on the host, nvm prefers
// `git clone https://github.com/nvm-sh/nvm.git`. git runs for real, so the
// parsed host gate is Policy.GitHosts — clear it and the clone
// is refused before it reaches the network, and nvm exits with nothing
// installed. (With the default GitHosts, GitHub is allowed and the clone would
// really happen; that is the policy's job, not the allow-list's.)
func TestNVMGitInstallHeldByEgressGuard(t *testing.T) {
	var home string
	out, er, err := runConfined(t, fixture(t, "nvm.sh"), withHome(t, "SHELL=/bin/bash"), func(c *Config) {
		c.Network.GitHosts = nil
		c.Mock(MatchName("xcode-select"), "/Library/Developer/CommandLineTools\n", "", 0)
		home = c.Dir
	})
	if err == nil {
		t.Fatalf("expected the clone to be refused; got success\n%s", out)
	}
	if !strings.Contains(er, "network egress denied: git → https://github.com/nvm-sh/nvm.git") {
		t.Errorf("expected the egress guard to name the remote; stderr:\n%s", er)
	}
	if !strings.Contains(er, "Failed to clone nvm repo") {
		t.Errorf("expected nvm to report the failed clone; stderr:\n%s", er)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".nvm", ".git")); statErr == nil {
		t.Error("~/.nvm/.git exists — the clone was not held")
	}
}

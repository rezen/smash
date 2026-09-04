package sandbox

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
)

func TestBashVersionVisibleAndUnexported(t *testing.T) {
	script := `
[ -n "${BASH_VERSION}" ] || { echo missing; exit 1; }
sh -c '[ -n "$BASH_VERSION" ] && echo sub-ok'
env | grep -q '^BASH_VERSION=' && echo exported
echo "v=$BASH_VERSION"
`
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Allowed = cfg.Allowed.With("env", "grep")
	out := &lockedBuffer{}
	cfg.Stdout, cfg.Stderr = out, &lockedBuffer{}
	if err := Run(cfg, "test", script); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got := out.String()
	for _, want := range []string{"sub-ok\n", "v=" + bashVersion + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "exported") {
		t.Errorf("BASH_VERSION leaked into exec environment:\n%s", got)
	}
}

func TestBashVersionCallerOverride(t *testing.T) {
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin", "BASH_VERSION=3.2.57(1)-release"))
	cfg.Stdout, cfg.Stderr = &lockedBuffer{}, &lockedBuffer{}
	vars, err := RunVars(cfg, "test", ":")
	if err != nil {
		t.Fatal(err)
	}
	if got := vars["BASH_VERSION"].String(); got != "3.2.57(1)-release" {
		t.Errorf("BASH_VERSION = %q, want caller's value", got)
	}
}

func TestPosixlyCorrectFollowsShebang(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"sh", "#!/bin/sh\n:", true},
		{"env sh", "#!/usr/bin/env sh\n:", true},
		{"bash", "#!/bin/bash\n:", false},
		{"env bash", "#!/usr/bin/env bash\n:", false},
		{"none", ":", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin"))
			cfg.Stdout, cfg.Stderr = &lockedBuffer{}, &lockedBuffer{}
			vars, err := RunVars(cfg, "test", tc.src)
			if err != nil {
				t.Fatal(err)
			}
			if got := vars["POSIXLY_CORRECT"].IsSet(); got != tc.want {
				t.Errorf("POSIXLY_CORRECT set = %v, want %v", got, tc.want)
			}
			if !vars["BASH_VERSION"].IsSet() {
				t.Error("BASH_VERSION missing")
			}
		})
	}
}

func TestPosixlyCorrectShDashC(t *testing.T) {
	script := `#!/bin/bash
[ -z "${POSIXLY_CORRECT+x}" ] && echo top-bash
sh -c '[ "$POSIXLY_CORRECT" = y ] && echo sub-sh'
bash -c '[ -z "${POSIXLY_CORRECT+x}" ] && echo sub-bash'
`
	cfg := NewConfig(t.TempDir(), t.TempDir(), expand.ListEnviron("PATH=/usr/bin:/bin"))
	out := &lockedBuffer{}
	cfg.Stdout, cfg.Stderr = out, &lockedBuffer{}
	if err := Run(cfg, "test", script); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got, want := out.String(), "top-bash\nsub-sh\nsub-bash\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

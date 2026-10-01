package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withFakeDocker puts a stand-in `docker` on the sandbox PATH. get-docker only
// prints its "docker already exists" warning — and runs the 20s countdown the
// cap assertion is about — when it finds one, so without this the test would
// depend on whether the host has Docker installed (a developer Mac does; the
// macOS CI runner does not).
func withFakeDocker(t *testing.T) option {
	t.Helper()
	return func(cfg *Config) {
		bin := filepath.Join(cfg.Root, "home", "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeBinary("docker")), 0o755); err != nil {
			t.Fatal(err)
		}
		cfg.Env = envWith(cfg.Env, "PATH="+bin+":"+strings.TrimPrefix(hostPath, "PATH="))
	}
}

// ubuntuEmulation fakes just enough Linux for get-docker to get past its
// OS/distro detection on a non-Linux host: a Linux `uname` and a virtual
// /etc/os-release identifying Ubuntu (served to stat, access, and open).
func ubuntuEmulation() Emulation {
	return Emulation{
		UnameOS:   "Linux",
		UnameArch: "x86_64",
		Files: map[string]string{
			"/etc/os-release": "ID=ubuntu\nVERSION_ID=\"22.04\"\nVERSION_CODENAME=jammy\nID_LIKE=debian\n",
		},
	}
}

// TestGetDockerLinuxContained runs Docker's get-docker script under Linux/Ubuntu
// emulation. It clears OS + distro detection (which bailed with "Unsupported"
// without emulation), its 20s warning countdown is capped, and it advances into
// the Debian install path — where the allow-list contains it at the first
// package tool it isn't granted (`dpkg`). Nothing was actually installed, no
// real sudo escalated, and no real time was burned.
func TestGetDockerLinuxContained(t *testing.T) {
	out, er, err := runConfined(t, fixture(t, "get-docker"),
		withHome(t, "SHELL=/bin/sh", "CHANNEL=stable"),
		withFakeDocker(t),
		func(c *Config) {
			c.Allowed = c.Allowed.With("which")
			c.Emulation = ubuntuEmulation()
		})
	combined := out + er
	if err == nil {
		t.Fatalf("expected get-docker to be contained; got success\n%s", combined)
	}
	if strings.Contains(combined, "Unsupported") {
		t.Errorf("emulation should clear OS/distro detection; output:\n%s", combined)
	}
	if !strings.Contains(er, "capped sleep") {
		t.Errorf("expected the 20s warning sleep to be capped; stderr:\n%s", er)
	}
	if !strings.Contains(er, "blocked command: dpkg") {
		t.Errorf("expected containment at dpkg in the Debian install path; stderr:\n%s", er)
	}
}

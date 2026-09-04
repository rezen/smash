package sandbox

import (
	"strings"
	"testing"
)

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

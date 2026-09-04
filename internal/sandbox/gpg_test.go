package sandbox

import (
	"os/exec"
	"strings"
	"testing"
)

// TestGPGAllowListedKeyserverOpsDenied: gpg is on the default allow-list for
// the offline work installers do (`--import` from a piped key, `--verify` of a
// detached signature), but gpg is also a network client. Every argument that
// makes it talk to a keyserver — or fetch a key by URL — is judged by the
// egress guard, which runs before the allow-list: the invocation is refused
// with the argument named, and no gpg process is started (so this part needs
// no gpg on the host). A keyserver on the URL allow-list is the only way
// through.
func TestGPGAllowListedKeyserverOpsDenied(t *testing.T) {
	if !DefaultAllowList()["gpg"] {
		t.Fatal("gpg should be on the default allow-list")
	}
	denied := []struct{ script, target string }{
		{"gpg --recv-keys 0xDEADBEEF", "--recv-keys"},
		{"gpg --keyserver hkps://keys.openpgp.org --recv-keys 0xDEADBEEF", "hkps://keys.openpgp.org"},
		{"gpg --search-keys someone@example.com", "--search-keys"},
		{"gpg --send-keys 0xDEADBEEF", "--send-keys"},
		{"gpg --fetch-keys https://example.com/key.asc", "--fetch-keys"},
		{"gpg --refresh-keys", "--refresh-keys"},
		{"gpg --locate-keys someone@example.com", "--locate-keys"},
		{"gpg --locate-external-keys someone@example.com", "--locate-external-keys"},
		{"gpg --auto-key-retrieve --verify f.sig f", "--auto-key-retrieve"},
		{"gpg2 --recv-keys 0xDEADBEEF", "--recv-keys"},
		{"sudo gpg --recv-keys 0xDEADBEEF", "--recv-keys"}, // unwrapped first
	}
	for _, tc := range denied {
		_, er, err := runConfined(t, tc.script)
		if err == nil || !strings.Contains(er, "network egress denied: gpg") || !strings.Contains(er, "→ "+tc.target) {
			t.Errorf("%s: expected egress denial naming %q; err=%v stderr=%q", tc.script, tc.target, err, er)
		}
	}

	// With the keyserver on the URL allow-list, the guard lets it through
	// (and it then reaches the allow-listed binary, or its absence).
	_, er, _ := runConfined(t, "gpg --keyserver hkps://keys.openpgp.org --recv-keys 0xDEADBEEF", func(c *Config) {
		c.Network.AllowedPrefixes = append(c.Network.AllowedPrefixes, "hkps://keys.openpgp.org")
	})
	if strings.Contains(er, "network egress denied") {
		t.Errorf("an allow-listed keyserver should pass the egress guard; stderr=%q", er)
	}

	// The offline forms run the real binary.
	if _, err := exec.LookPath("gpg"); err != nil {
		t.Skip("gpg not installed on host; offline-form check skipped")
	}
	out, er, err := runConfined(t, "gpg --version | head -n1", withHome(t))
	if err != nil || !strings.HasPrefix(out, "gpg (GnuPG)") {
		t.Errorf("offline gpg should run: err=%v out=%q stderr=%q", err, out, er)
	}
}

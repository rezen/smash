package network

import "testing"

func TestHostFromEndpoint(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		// URLs
		{"https://Example.COM/path", "example.com"},
		{"https://example.com:8443/x", "example.com"},
		{"https://user:pw@example.com/x", "example.com"},
		{"https://example.com./x", "example.com"},
		{"https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"http://%zz/", ""}, // unparseable
		// endpoints
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"example.com:443", "example.com"},
		{"user@example.com", "example.com"},
		{"user@example.com:22", "example.com"},
		{"1.2.3.4", "1.2.3.4"},
		{"1.2.3.4:80", "1.2.3.4"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		// not hosts
		{"/tmp/file", ""},
		{"two words", ""},
		{"", ""},
		// QUIRK, preserved from the pre-extraction parsers: SplitHostPort
		// does not require a numeric port, so a path with a colon "parses".
		// Harmless — ValidHost rejects "dir/file" as an allow-list entry —
		// but a tightening (reject "/" after the split) is a behavior change
		// and belongs to its own decision, not to this refactor.
		{"dir/file:name", "dir/file"},
	}
	for _, c := range cases {
		if got := HostFromEndpoint(c.target); got != c.want {
			t.Errorf("HostFromEndpoint(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}

func TestHostFromGitRemote(t *testing.T) {
	cases := []struct {
		target, want string
	}{
		{"https://GitHub.com/x/y.git", "github.com"},
		{"ssh://git@github.com:2222/x/y.git", "github.com"},
		{"git@github.com:x/y.git", "github.com"},
		{"github.com:x/y.git", "github.com"},
		{"http://%zz/", ""},
		// a remote NAME, not a host: the caller resolves it via .git/config
		{"origin", ""},
		{"upstream", ""},
		// local paths never name a host
		{"./repo:dir", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := HostFromGitRemote(c.target); got != c.want {
			t.Errorf("HostFromGitRemote(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}

func TestValidHost(t *testing.T) {
	valid := []string{"example.com", "1.2.3.4", "2001:db8::1", "a"}
	for _, h := range valid {
		if !ValidHost(h) {
			t.Errorf("ValidHost(%q) = false, want true", h)
		}
	}
	invalid := []string{"", "example.com/x", "user@example.com", "two words", `a\b`, "example.com:443"}
	for _, h := range invalid {
		if ValidHost(h) {
			t.Errorf("ValidHost(%q) = true, want false", h)
		}
	}
}

// TestEndpointMatchesRecording pins the property the host functions exist
// for: what the Profiler records for a target is exactly what enforcement
// extracts from the same target later — one function, so it holds by
// construction, and this test keeps anyone from splitting it back into two.
func TestEndpointMatchesRecording(t *testing.T) {
	targets := []string{
		"https://example.com/x", "user@example.com:22", "[2001:db8::1]:443",
	}
	for _, target := range targets {
		host := HostFromEndpoint(target)
		if host == "" {
			t.Fatalf("HostFromEndpoint(%q) = %q; test target must parse", target, host)
		}
		if !ValidHost(host) {
			t.Errorf("HostFromEndpoint(%q) = %q, which ValidHost rejects: recorded manifests would fail validation", target, host)
		}
		if again := HostFromEndpoint(host); again != host {
			t.Errorf("HostFromEndpoint is not idempotent for %q: %q → %q", target, host, again)
		}
	}
}

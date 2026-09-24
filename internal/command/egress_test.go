package command

import "testing"

// TestEgressInfo pins the classification of each command family's targets:
// URLs and endpoints are matchable places, indicators are operation labels a
// guard must deny unconditionally. A module or subcommand label that READS
// like a bare hostname ("socket", "install", "s_client") must classify as an
// indicator, never as an endpoint — that is the mistake shape-only
// classification would make and EgressClassifier exists to prevent.
func TestEgressInfo(t *testing.T) {
	kindNames := map[EgressKind]string{
		EgressIndicator: "indicator", EgressEndpoint: "endpoint", EgressURL: "url",
	}
	cases := []struct {
		argv   []string
		target string
		kind   EgressKind
	}{
		// downloaders and endpoint dialers: shape classification
		{[]string{"curl", "https://example.com/x"}, "https://example.com/x", EgressURL},
		{[]string{"curl", "example.com"}, "example.com", EgressEndpoint},
		{[]string{"ssh", "user@host", "ls"}, "user@host", EgressEndpoint},
		{[]string{"nc", "1.2.3.4", "4444"}, "1.2.3.4:4444", EgressEndpoint},
		{[]string{"rsync", "-a", "host:src", "dst"}, "host:src", EgressEndpoint},
		// openssl: -connect is a place; a bare s_client is a label
		{[]string{"openssl", "s_client", "-connect", "example.com:443"}, "example.com:443", EgressEndpoint},
		{[]string{"openssl", "s_client"}, "s_client", EgressIndicator},
		// package managers: subcommands are labels, URL operands are places
		{[]string{"apt-get", "install", "docker-ce"}, "install", EgressIndicator},
		{[]string{"pip", "install", "https://example.com/x.whl"}, "https://example.com/x.whl", EgressURL},
		{[]string{"pacman", "-S", "docker"}, "-S", EgressIndicator},
		// gpg: the net-op flag is a label, a named keyserver is a place
		{[]string{"gpg", "--recv-keys", "0xABCD"}, "--recv-keys", EgressIndicator},
		{[]string{"gpg", "--keyserver", "hkps://keys.openpgp.org", "--recv-keys", "0xABCD"}, "hkps://keys.openpgp.org", EgressURL},
		// interpreters: module labels vs dialled endpoints vs URLs in code
		{[]string{"perl", "-MLWP::Simple", "-e", "1"}, "LWP::Simple", EgressIndicator},
		{[]string{"perl", "-e", `get("https://example.com/x")`}, "https://example.com/x", EgressURL},
		{[]string{"python3", "-m", "http.server", "8000"}, "http.server 8000", EgressIndicator},
		{[]string{"python3", "-c", "import socket"}, "socket", EgressIndicator},
		{[]string{"python3", "-c", `import socket;s.connect(("10.0.0.1",4444))`}, "10.0.0.1:4444", EgressEndpoint},
		// git: remote NAMES are labels (resolved via .git/config); URLs and
		// scp-like remotes are places
		{[]string{"git", "clone", "https://github.com/x/y"}, "https://github.com/x/y", EgressURL},
		{[]string{"git", "clone", "git@github.com:x/y.git"}, "git@github.com:x/y.git", EgressEndpoint},
		{[]string{"git", "fetch", "origin"}, "origin", EgressIndicator},
		{[]string{"git", "submodule", "update"}, "submodule", EgressIndicator},
	}
	for _, c := range cases {
		egress, networked := Parse(c.argv).EgressInfo()
		if !networked {
			t.Errorf("%v: EgressInfo reports not networked", c.argv)
			continue
		}
		if egress.Target != c.target || egress.Kind != c.kind {
			t.Errorf("%v: egress = %q (%s), want %q (%s)",
				c.argv, egress.Target, kindNames[egress.Kind], c.target, kindNames[c.kind])
		}
	}
}

func TestEgressInfoNotNetworked(t *testing.T) {
	for _, argv := range [][]string{
		{"tar", "xf", "a.tgz"},
		{"apt-cache", "show", "docker-ce"},
		{"gpg", "--verify", "sig", "file"},
	} {
		if egress, networked := Parse(argv).EgressInfo(); networked {
			t.Errorf("%v: unexpectedly networked → %q", argv, egress.Target)
		}
	}
}

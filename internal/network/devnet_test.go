package network

import "testing"

func TestParseDevNet(t *testing.T) {
	cases := []struct {
		name              string
		proto, host, port string
		ok                bool
	}{
		{"/dev/tcp/1.2.3.4/4444", "tcp", "1.2.3.4", "4444", true},
		{"/dev/udp/resolver.test/53", "udp", "resolver.test", "53", true},
		{"/dev/./tcp/host/80", "tcp", "host", "80", true}, // cleaned first
		{"/dev/tcp/host", "", "", "", false},              // no port
		{"/dev/tcp/host/80/x", "", "", "", false},
		{"/dev/tcp//80", "", "", "", false},
		{"dev/tcp/host/80", "", "", "", false}, // relative: not the device
		{"/dev/sda", "", "", "", false},
		{"/tmp/file", "", "", "", false},
	}
	for _, c := range cases {
		proto, host, port, ok := ParseDevNet(c.name)
		if proto != c.proto || host != c.host || port != c.port || ok != c.ok {
			t.Errorf("ParseDevNet(%q) = %q, %q, %q, %v; want %q, %q, %q, %v",
				c.name, proto, host, port, ok, c.proto, c.host, c.port, c.ok)
		}
	}
}

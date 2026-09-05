package sandbox

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// DefaultDNSServer is Quad9's malware-blocking, DNSSEC-validating resolver.
// An empty Policy.DNSServer opts back into the host's system resolver.
const DefaultDNSServer = "9.9.9.9:53"

// NewHTTPClient builds the transport shared by initial script loading and the
// sandbox's in-process curl/wget implementation. dnsServer must be an IP
// literal with an optional port; an empty value uses the system resolver.
func NewHTTPClient(timeout time.Duration, dnsServer string) (*http.Client, error) {
	endpoint, err := normalizeDNSServer(dnsServer)
	if err != nil {
		return nil, err
	}

	var resolver *net.Resolver
	if endpoint != "" {
		dnsDialer := &net.Dialer{Timeout: 5 * time.Second}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Preserve udp/tcp so the Go resolver can retry a truncated UDP
				// response over TCP, but always dial the configured endpoint.
				return dnsDialer.DialContext(ctx, network, endpoint)
			},
		}
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, Resolver: resolver}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DialContext:       dialer.DialContext,
			ForceAttemptHTTP2: true,
		},
	}, nil
}

// ValidateDNSServer checks the spelling accepted by NewHTTPClient.
func ValidateDNSServer(server string) error {
	_, err := normalizeDNSServer(server)
	return err
}

func normalizeDNSServer(server string) (string, error) {
	if server == "" {
		return "", nil
	}
	if addr, err := netip.ParseAddr(server); err == nil {
		return netip.AddrPortFrom(addr, 53).String(), nil
	}
	addrPort, err := netip.ParseAddrPort(server)
	if err != nil || addrPort.Port() == 0 {
		return "", fmt.Errorf("DNS server %q must be an IP literal with an optional non-zero port (for example 9.9.9.9 or [2620:fe::fe]:53); use an empty value for the system resolver", server)
	}
	return addrPort.String(), nil
}

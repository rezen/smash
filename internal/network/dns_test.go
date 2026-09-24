package network

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestDNSServerValidation(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"9.9.9.9":            "9.9.9.9:53",
		"1.1.1.2:5353":       "1.1.1.2:5353",
		"2620:fe::fe":        "[2620:fe::fe]:53",
		"[2620:fe::fe]:5353": "[2620:fe::fe]:5353",
	}
	for input, want := range cases {
		got, err := normalizeDNSServer(input)
		if err != nil || got != want {
			t.Errorf("normalizeDNSServer(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"dns.example", "9.9.9.9:0", "9.9.9.9:nope", " 9.9.9.9"} {
		if err := ValidateDNSServer(input); err == nil {
			t.Errorf("ValidateDNSServer(%q) accepted an invalid endpoint", input)
		}
	}
}

func TestHTTPClientUsesConfiguredDNS(t *testing.T) {
	dns := newTestDNSServer(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "resolved")
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewHTTPClient(2*time.Second, dns)
	if err != nil {
		t.Fatal(err)
	}
	// Do not let a test runner's HTTP_PROXY resolve the destination instead.
	client.Transport.(*http.Transport).Proxy = nil
	resp, err := client.Get("http://installer.test:" + port)
	if err != nil {
		t.Fatalf("request through configured DNS: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "resolved" {
		t.Fatalf("body = %q, %v", body, err)
	}
}

// newTestDNSServer returns a UDP resolver that answers A questions with
// 127.0.0.1 and returns an empty success for other record types.
func newTestDNSServer(t *testing.T) string {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, addr, err := packet.ReadFrom(buf)
			if err != nil {
				return
			}
			if response := dnsResponse(buf[:n]); response != nil {
				packet.WriteTo(response, addr)
			}
		}
	}()
	t.Cleanup(func() {
		packet.Close()
		<-done
	})
	return packet.LocalAddr().String()
}

func dnsResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	pos := 12
	for pos < len(query) && query[pos] != 0 {
		pos += int(query[pos]) + 1
	}
	pos++
	if pos+4 > len(query) {
		return nil
	}
	questionEnd := pos + 4
	isA := binary.BigEndian.Uint16(query[pos:pos+2]) == 1
	response := make([]byte, 12, 64)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180) // response, recursion available, no error
	binary.BigEndian.PutUint16(response[4:6], 1)
	if isA {
		binary.BigEndian.PutUint16(response[6:8], 1)
	}
	response = append(response, query[12:questionEnd]...)
	if isA {
		response = append(response,
			0xc0, 0x0c, // compressed name: the question at offset 12
			0x00, 0x01, // A
			0x00, 0x01, // IN
			0x00, 0x00, 0x00, 0x3c, // 60-second TTL
			0x00, 0x04,
			127, 0, 0, 1,
		)
	}
	return response
}

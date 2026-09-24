// Package hostname is the one spelling of "extract the host from a target
// string". It exists because the two sides of the profile/enforce boundary
// must agree byte-for-byte: the manifest Profiler records the hosts a run
// touched with these rules, and Policy.AllowsTarget later matches targets
// against that recorded list with the same rules. Two hand-kept copies of
// this parsing (ports, IPv6 brackets, userinfo, trailing dots) would let the
// halves drift apart, and a drifted pair fails closed but inexplicably: a
// profiled manifest starts denying hosts it just recorded.
//
// Results are canonical: lower-case, no trailing dot, no port, no userinfo.
package hostname

import (
	"net"
	"net/url"
	"strings"
)

// FromEndpoint extracts the host from a download or connection target: a URL,
// [user@]host, host:port, a bracketed or bare IPv6 literal — the shapes
// curl/ssh/nc/database-client arguments take. It returns "" when the target
// does not name a host (a path, a label, free text).
func FromEndpoint(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	}
	rest := target
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	if h := strings.Trim(rest, "[]"); net.ParseIP(h) != nil {
		return strings.ToLower(h)
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		return strings.ToLower(strings.TrimSuffix(h, "."))
	}
	if h, _, ok := strings.Cut(rest, ":"); ok {
		rest = h
	}
	if strings.ContainsAny(rest, "/ ") {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(rest, "[]"), "."))
}

// FromGitRemote extracts the host from a git remote: scheme://[user@]host[:port]/path
// or the scp-like [user@]host:path. Unlike FromEndpoint it requires the
// remote SHAPE — a bare word without a colon ("origin") is a remote NAME,
// not a host, and returns "" so the caller resolves it through .git/config.
func FromGitRemote(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Hostname())
	}
	rest := target
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	host, _, ok := strings.Cut(rest, ":")
	if !ok || host == "" || strings.ContainsAny(host, "/ ") {
		return ""
	}
	return strings.ToLower(host)
}

// Valid reports whether host is a plausible bare host for an allow-list
// entry: non-empty, no path/userinfo/space characters, and a colon only as
// part of an IPv6 literal — never a port, which would silently fail to match
// the port-stripped output of FromEndpoint.
func Valid(host string) bool {
	if host == "" || strings.ContainsAny(host, "/@ \\") {
		return false
	}
	return !strings.Contains(host, ":") || net.ParseIP(host) != nil
}

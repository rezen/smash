package network

import (
	"net"
	"net/url"
	"strings"
)

// HostFromEndpoint extracts the host from a download or connection target: a
// URL, [user@]host, host:port, a bracketed or bare IPv6 literal — the shapes
// curl/ssh/nc/database-client arguments take. It returns "" when the target
// does not name a host (a path, a label, free text).
func HostFromEndpoint(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		return HostFromURL(u)
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

// HostFromURL is HostFromEndpoint for an already-parsed URL: lower-case,
// trailing dot and port stripped.
func HostFromURL(u *url.URL) string {
	return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
}

// HostFromGitRemote extracts the host from a git remote: scheme://[user@]host[:port]/path
// or the scp-like [user@]host:path. Unlike HostFromEndpoint it requires the
// remote SHAPE — a bare word without a colon ("origin") is a remote NAME,
// not a host, and returns "" so the caller resolves it through .git/config.
func HostFromGitRemote(target string) string {
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

// ValidHost reports whether host is a plausible bare host for an allow-list
// entry: non-empty, no path/userinfo/space characters, and a colon only as
// part of an IPv6 literal — never a port, which would silently fail to match
// the port-stripped output of HostFromEndpoint.
func ValidHost(host string) bool {
	if host == "" || strings.ContainsAny(host, "/@ \\") {
		return false
	}
	return !strings.Contains(host, ":") || net.ParseIP(host) != nil
}

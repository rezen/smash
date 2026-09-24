package command

// Egress classification. A Networked command's target string carries one of
// three different kinds of value, and a guard must treat them differently:
//
//   - a URL ("https://x/y") — matchable against a URL prefix allow-list;
//   - an endpoint ("host", "host:port", "user@host") — matchable against a
//     host allow-list;
//   - an INDICATOR — a label that names the networked operation rather than
//     where it goes: a subcommand ("install"), a flag ("--recv-keys"), a
//     module ("LWP::Simple", "http.server 8000"), "submodule". No allow-list
//     entry can name an indicator, so it is off-policy by definition.
//
// Without the kind, an indicator is denied only because a label happens
// never to match a host list — correct, but emergent. EgressInfo makes the
// distinction explicit: most targets classify by shape (ClassifyEgress), and
// the commands whose labels LOOK like hosts ("socket", "install") say so
// themselves via EgressClassifier. The EgressKind implementations live
// together below, like the Describers in describe.go, so the labelling rules
// are easiest to compare side by side.

import (
	"strings"

	"github.com/rezen/smash/internal/network"
)

// EgressKind says what shape of thing an egress target is.
type EgressKind int

const (
	// EgressIndicator names the networked operation, not a place. Never
	// matchable by an allow-list; a guard denies it unconditionally.
	EgressIndicator EgressKind = iota
	// EgressEndpoint is a host, host:port or user@host to be matched against
	// a host allow-list.
	EgressEndpoint
	// EgressURL is a full URL to be matched against a URL prefix allow-list.
	EgressURL
)

// Egress is one classified egress: where (or what) plus which kind of where.
type Egress struct {
	Target string
	Kind   EgressKind
}

// EgressClassifier is implemented by Networked commands whose targets cannot
// be classified by shape alone — module and subcommand labels that would
// otherwise read as bare hostnames.
type EgressClassifier interface {
	EgressKind(p ParsedCommand, target string) EgressKind
}

// EgressInfo is Egress() with the target classified. The command's own
// EgressClassifier wins; otherwise the target's shape decides.
func (p ParsedCommand) EgressInfo() (Egress, bool) {
	target, networked := p.Egress()
	if !networked {
		return Egress{}, false
	}
	kind := ClassifyEgress(target)
	if c, ok := p.cmd.(EgressClassifier); ok {
		kind = c.EgressKind(p, target)
	}
	return Egress{Target: target, Kind: kind}, true
}

// ClassifyEgress classifies a target by shape: a scheme makes a URL, a
// parseable host an endpoint, anything else an indicator.
func ClassifyEgress(target string) EgressKind {
	if strings.Contains(target, "://") {
		return EgressURL
	}
	if network.HostFromEndpoint(target) != "" {
		return EgressEndpoint
	}
	return EgressIndicator
}

// Openssl: `s_client`/`s_server`/`s_time` with no -connect report the
// subcommand itself — an indicator, though it reads as a bare host.
func (Openssl) EgressKind(p ParsedCommand, target string) EgressKind {
	if target == p.Subcommand {
		return EgressIndicator
	}
	return ClassifyEgress(target)
}

// Git: URLs and scp-like remotes are places; a remote NAME ("origin"),
// "submodule" and "unsafe git config" are indicators. The guard's git branch
// resolves indicator names through .git/config before judging.
func (Git) EgressKind(_ ParsedCommand, target string) EgressKind {
	if strings.Contains(target, "://") {
		return EgressURL
	}
	if network.HostFromGitRemote(target) != "" {
		return EgressEndpoint
	}
	return EgressIndicator
}

// Perl reports a module name or "socket" — labels — unless the inline code
// carried a literal URL.
func (Perl) EgressKind(_ ParsedCommand, target string) EgressKind {
	if strings.Contains(target, "://") {
		return EgressURL
	}
	return EgressIndicator
}

// Python reports module labels ("http.server 8000", "socket", "requests")
// as indicators; a dialled host:port from a connect tuple, or a URL in the
// code, classifies by shape.
func (Python) EgressKind(_ ParsedCommand, target string) EgressKind {
	module, _, _ := strings.Cut(target, " ")
	if isPythonNetModule(module) {
		return EgressIndicator
	}
	return ClassifyEgress(target)
}

// PackageManager reports a subcommand, a flag or a package name — all
// indicators — unless the operand was a literal URL (pip install https://…).
func (PackageManager) EgressKind(_ ParsedCommand, target string) EgressKind {
	if strings.Contains(target, "://") {
		return EgressURL
	}
	return EgressIndicator
}

// Gpg reports the keyserver when one is named; otherwise the net-op flag
// itself, which is an indicator.
func (Gpg) EgressKind(_ ParsedCommand, target string) EgressKind {
	if strings.HasPrefix(target, "--") {
		return EgressIndicator
	}
	return ClassifyEgress(target)
}

package sandbox

// Network policy and egress enforcement. curl/wget are never delegated to
// host binaries (which can reach any URL): in BOTH modes the tool package
// takes their parsed Request and drives a configurable net/http.Client.
// Enforcing runs use httpMiddleware — allow-list, redirect policy, timeout,
// size cap, header injection and transport (proxy/TLS/DNS) all enforced
// here. Profile runs use observeHTTPMiddleware: the same downloader with
// every URL/method/type admitted, so discovery exercises exactly the
// implementation a manifest will later be enforced against, and responses
// (content types, redirect hops) are observable. Other network-capable
// commands (openssl s_client, ssh, nc, git clone) are denied by
// egressGuardMiddleware using the same Policy — in enforcing mode only.

import (
	"context"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/gitconfig"
	"github.com/rezen/smash/internal/network"
	"github.com/rezen/smash/internal/pathsafe"
	"github.com/rezen/smash/internal/tool"
)

// Policy is the network policy: what a sandboxed fetch may reach and how.
type Policy struct {
	// AllowedPrefixes are the URL prefixes a fetch may reach. An entry is
	// matched STRUCTURALLY, not as text: the scheme and the host (with any
	// explicit non-default port) must match exactly, and the entry's path must
	// be a whole-segment prefix of the request's. So
	// "https://example.com/pkg" admits "https://example.com/pkg" and
	// "https://example.com/pkg/v1" but neither "https://example.com/pkgs" nor
	// "https://example.com.evil.test/pkg". A trailing slash on an entry means
	// nothing; name a subdomain explicitly rather than expecting one to be
	// covered by its parent. Use Validate to reject entries that are not URL
	// prefixes at all — those match nothing. See Allows.
	AllowedPrefixes []string
	// AllowedHosts grants every HTTP(S) URL on an exact host. It is primarily
	// used by a generated profile manifest, whose contract records hosts rather
	// than paths. Unlike GitHosts, parent hosts do not grant subdomains.
	AllowedHosts   []string
	AllowedMethods map[string]bool // HTTP methods a downloader may use
	// AllowedMIMETypes is the response-body MIME allow-list the in-process
	// downloaders enforce: the declared Content-Type (parameters ignored,
	// case-insensitive) must match an entry, and the body's first bytes must
	// not sniff as a disallowed type. Entries are exact media types
	// ("application/gzip") or a subtype wildcard ("application/*"). nil means
	// no restriction; an empty non-nil list denies every response body — the
	// same nil-vs-empty rule AllowedPrefixes has. NOTE the inversion relative
	// to AllowedMethods, where nil denies: an absent MIME policy must stay a
	// no-op. See AllowsMIME.
	AllowedMIMETypes []string
	MaxResponse      int64         // response body cap in bytes
	MaxRequest       int64         // request body cap in bytes
	Timeout          time.Duration // per-request timeout
	// DNSServer is the IP[:port] used by the in-process HTTP client. Empty uses
	// the host's system resolver. DefaultPolicy selects a malware-blocking DNS.
	DNSServer string
	// InjectHeaders are added to every request (e.g. a broker token) so secrets
	// never have to appear in the sandboxed script itself.
	InjectHeaders map[string]string
	// GitHosts are advisory checks for an explicitly allowed real git process.
	// They are the hosts git may clone/fetch/push to, over any transport
	// (https, ssh, git://, scp-like user@host:path); a subdomain of a listed
	// host counts. Git is not a downloader, so it bypasses the in-process HTTP
	// client. These checks are defense in depth for explicitly granted real
	// Git, not an OS-level egress boundary. See AllowsGit.
	GitHosts []string
}

// DefaultGitHosts are the forges git may reach unless Policy.GitHosts says
// otherwise: GitHub, GitLab and Bitbucket.
func DefaultGitHosts() []string { return []string{"github.com", "gitlab.com", "bitbucket.org"} }

// GitHubPrefixes are the URL prefixes a release download from GitHub can
// touch: the release page and its redirect (github.com), the API (api.github.com),
// raw files and the asset hosts. Append them to Policy.AllowedPrefixes when an
// installer fetches its binary from GitHub Releases — the CLI's -urls-github.
func GitHubPrefixes() []string {
	return []string{
		"https://github.com/",
		"https://api.github.com/",
		"https://raw.githubusercontent.com/",
		"https://codeload.github.com/",
		"https://objects.githubusercontent.com/",
		"https://release-assets.githubusercontent.com/",
	}
}

// DefaultPolicy is the policy NewConfig starts from: GET/HEAD only, the usual
// caps, the default git forges, and the GitHub hosts a release download goes
// through — the release page, raw files, and the asset host it redirects to.
// That is the part of an installer's reach which is the same for everyone; a
// vendor's own release host is not, and belongs in -urls (or
// Policy.AllowedPrefixes) where the user names it. -urls-github widens this to
// the rest of the GitHub set (see GitHubPrefixes).
func DefaultPolicy() Policy {
	return Policy{
		AllowedPrefixes: []string{
			"https://github.com",
			"https://raw.githubusercontent.com/",
			"https://objects.githubusercontent.com/",
		},
		AllowedMethods: map[string]bool{"GET": true, "HEAD": true},
		MaxResponse:    200 << 20, // 200 MiB
		MaxRequest:     8 << 20,   // 8 MiB
		Timeout:        60 * time.Second,
		DNSServer:      network.DefaultDNSServer,
		GitHosts:       DefaultGitHosts(),
	}
}

// Allows reports whether u may be fetched: some AllowedPrefixes entry matches
// it, and the URL is unambiguous about where it goes (see disguisesItsHost).
func (p Policy) Allows(u *url.URL) bool {
	if u == nil || disguisesItsHost(u) {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, allowed := range p.AllowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(allowed, ".")) {
			return true
		}
	}
	for _, pre := range p.AllowedPrefixes {
		if r, ok := parseURLRule(pre); ok && r.allows(u) {
			return true
		}
	}
	return false
}

// AllowsMIME reports whether a response media type is admitted. mediaType may
// carry parameters ("text/plain; charset=utf-8"); they are stripped, and the
// comparison is case-insensitive. A nil AllowedMIMETypes admits everything
// (no restriction); an empty non-nil list admits nothing. Callers that must
// distinguish "unset" from "deny all" check AllowedMIMETypes == nil
// themselves — httpMiddleware does.
func (p Policy) AllowsMIME(mediaType string) bool {
	if p.AllowedMIMETypes == nil {
		return true
	}
	mt, _, err := mime.ParseMediaType(strings.ToLower(mediaType))
	if err != nil {
		return false
	}
	major, _, _ := strings.Cut(mt, "/")
	for _, entry := range p.AllowedMIMETypes {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == mt || entry == major+"/*" {
			return true
		}
	}
	return false
}

// ValidateMIMERule vets one AllowedMIMETypes entry: a bare media type
// ("type/subtype") or the subtype wildcard ("type/*"). "*/*" is refused —
// omit the key to allow every type — as are parameters and bare tokens.
// Exported for the manifest package, which validates the same entries.
func ValidateMIMERule(entry string) error {
	e := strings.ToLower(strings.TrimSpace(entry))
	if major, ok := strings.CutSuffix(e, "/*"); ok {
		if major == "" || strings.ContainsAny(major, "*/") {
			return fmt.Errorf("invalid entry %q; a wildcard is type/* (and */* means the same as omitting the key)", entry)
		}
		return nil
	}
	mt, params, err := mime.ParseMediaType(e)
	if err != nil || strings.Count(mt, "/") != 1 || strings.Contains(mt, "*") {
		return fmt.Errorf("invalid entry %q; use type/subtype or type/*", entry)
	}
	if len(params) > 0 {
		return fmt.Errorf("invalid entry %q; parameters are ignored when matching, list the bare media type", entry)
	}
	return nil
}

// AllowsTarget permits allow-listed URLs and raw endpoints whose host appears
// in AllowedHosts. The host is extracted by network.HostFromEndpoint — the
// same rules the manifest Profiler records hosts with, so a profiled manifest
// matches at enforcement time by construction.
func (p Policy) AllowsTarget(target string) bool {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		return err == nil && p.Allows(u)
	}
	host := network.HostFromEndpoint(target)
	for _, allowed := range p.AllowedHosts {
		if host == strings.ToLower(strings.TrimSuffix(allowed, ".")) {
			return true
		}
	}
	return false
}

// Validate reports malformed URL prefixes and DNS resolver endpoints. A
// mistyped policy otherwise fails closed but silently, so callers taking the
// policy from a user should surface the error before starting a run.
func (p Policy) Validate() error {
	var bad []string
	for _, pre := range p.AllowedPrefixes {
		if _, ok := parseURLRule(pre); !ok {
			bad = append(bad, strconv.Quote(pre))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("URL allow-list needs a scheme on every entry (e.g. https://host/path); cannot use %s", strings.Join(bad, ", "))
	}
	for _, host := range p.AllowedHosts {
		if !network.ValidHost(host) {
			return fmt.Errorf("invalid allowed host %q", host)
		}
	}
	for _, entry := range p.AllowedMIMETypes {
		if err := ValidateMIMERule(entry); err != nil {
			return fmt.Errorf("mime-types: %w", err)
		}
	}
	return network.ValidateDNSServer(p.DNSServer)
}

// urlRule is one parsed AllowedPrefixes entry. Entries are parsed on every
// match rather than cached: a policy holds a handful of them and a run makes a
// handful of requests, so keeping AllowedPrefixes an ordinary []string a
// caller can assign to is worth more than the parse.
type urlRule struct {
	scheme string // lower-case, matched exactly
	host   string // lower-case host[:port], a default port removed
	path   string // cleaned path prefix; "" when the entry names the whole host
}

// parseURLRule parses one entry. ok is false when it is not a URL prefix.
func parseURLRule(prefix string) (urlRule, bool) {
	u, err := url.Parse(prefix)
	if err != nil || u.Scheme == "" || u.Opaque != "" || u.User != nil {
		return urlRule{}, false
	}
	r := urlRule{scheme: strings.ToLower(u.Scheme), host: canonicalHost(u)}
	if p := path.Clean(u.Path); p != "." && p != "/" {
		r.path = p
	}
	return r, true
}

// allows reports whether u falls under this entry. The path must match on
// whole segments, so /astral-sh does not admit /astral-shady.
func (r urlRule) allows(u *url.URL) bool {
	if strings.ToLower(u.Scheme) != r.scheme || canonicalHost(u) != r.host {
		return false
	}
	if r.path == "" {
		return true
	}
	p := path.Clean(u.Path)
	return p == r.path || strings.HasPrefix(p, r.path+"/")
}

// canonicalHost renders a URL's authority for comparison: lower-cased, with a
// port that is the scheme's default dropped — so https://x and https://x:443
// are one host, and https://x:8443 is not.
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || port == defaultPorts[strings.ToLower(u.Scheme)] {
		return host
	}
	return net.JoinHostPort(host, port)
}

var defaultPorts = map[string]string{"http": "80", "https": "443"}

// disguisesItsHost refuses the two URL shapes that READ as one host and
// RESOLVE as another — the failure mode of every allow-list that compares
// URLs as text:
//
//   - userinfo. "https://allowed.example@evil.example/x" has the allow-listed
//     name in it, and an HTTP client dials evil.example.
//   - a "." or ".." path segment, in raw or percent-encoded form.
//     "https://host/allowed/../evil" passes any path check and is normalised
//     by the server afterwards.
func disguisesItsHost(u *url.URL) bool {
	return u.User != nil || hasDotSegment(u.Path)
}

// hasDotSegment reports whether a path has a "." or ".." segment. url.Parse
// has already decoded percent-escapes into Path, so %2e%2e is caught here too.
func hasDotSegment(p string) bool {
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// AllowsGit permits a git remote whose host is one of GitHosts (or a subdomain
// of one), whatever the transport, and a file:// remote, which reaches no
// network at all. A remote NAME ("origin") names no host and is denied here;
// the egress guard first resolves names through the repository's .git/config
// (resolveGitRemote) and asks again with the URL.
//
// AllowedPrefixes deliberately does NOT grant git. The two lists answer
// different questions: the prefix list says which URLs the in-process HTTP
// client may GET, under its method, size and redirect policy; git is a
// separate binary opening its own connections with the user's own credentials,
// and it can push as well as fetch. Reading "you may download this URL" as
// "you may push a repository there" would make GitHosts unable to narrow
// anything the prefix list had already named.
func (p Policy) AllowsGit(target string) bool {
	if u, err := url.Parse(target); err == nil && strings.EqualFold(u.Scheme, "file") {
		return true
	}
	host := network.HostFromGitRemote(target)
	if host == "" {
		return false
	}
	for _, h := range p.GitHosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// client builds the http.Client with the policy applied. Everything you'd
// normally reach for on a client — Timeout, CheckRedirect, Transport
// (Proxy/TLSClientConfig/DialContext) — is wired here.
func (p Policy) client() (*http.Client, error) {
	client, err := network.NewHTTPClient(p.Timeout, p.DNSServer)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 20 {
			return fmt.Errorf("stopped after 20 redirects")
		}
		if !p.Allows(req.URL) { // re-check the allow-list on every hop
			return fmt.Errorf("redirect to disallowed URL: %s", req.URL)
		}
		return nil
	}
	return client, nil
}

// httpMiddleware supplies sandbox policy to the in-process curl/wget tools.
func httpMiddleware(p Policy, root string) (Middleware, error) {
	client, err := p.client()
	if err != nil {
		return nil, err
	}
	dc := tool.DownloaderConfig{
		Client:        client,
		AllowURL:      p.Allows,
		AllowPath:     func(target string) bool { return root == "" || pathsafe.Within(root, target) },
		AllowMethod:   func(method string) bool { return p.AllowedMethods[method] },
		MaxResponse:   p.MaxResponse,
		MaxRequest:    p.MaxRequest,
		InjectHeaders: p.InjectHeaders,
	}
	if p.AllowedMIMETypes != nil {
		// Installed only when the policy sets a list: a nil AllowMIME is how
		// the downloader knows no MIME restriction applies.
		dc.AllowMIME = p.AllowsMIME
	}
	return tool.Downloaders(dc), nil
}

// observeHTTPMiddleware is profile mode's downloader: the same in-process
// curl/wget as enforcement, with every URL, method and media type admitted,
// and the transport pinned to DefaultPolicy's DNS/timeout/caps rather than
// the (possibly under-construction) policy's network section — the same
// rationale as the CLI's effectiveDNS: profiling must not fail because the
// policy being authored names a broken resolver or an empty allow-list. Only
// InjectHeaders is taken from the policy, so authenticated downloads can be
// profiled. -o and @file paths remain confined to root: that is smash's own
// I/O safety, not script policy, and enforcement will hold the same line.
func observeHTTPMiddleware(p Policy, root string) (Middleware, error) {
	def := DefaultPolicy()
	client, err := network.NewHTTPClient(def.Timeout, def.DNSServer)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 20 {
			return fmt.Errorf("stopped after 20 redirects")
		}
		return nil
	}
	return tool.Downloaders(tool.DownloaderConfig{
		Client:        client,
		AllowURL:      func(*url.URL) bool { return true },
		AllowPath:     func(target string) bool { return root == "" || pathsafe.Within(root, target) },
		AllowMethod:   func(string) bool { return true },
		MaxResponse:   def.MaxResponse,
		MaxRequest:    def.MaxRequest,
		InjectHeaders: p.InjectHeaders,
	}), nil
}

// egressGuardMiddleware denies any network-capable command whose egress is
// off-policy — openssl s_client, ssh, nc, git clone — from ONE place, using
// the parser's classified Egress (command.EgressInfo). A URL target is
// matched against the prefix allow-list, an endpoint against AllowedHosts,
// and an INDICATOR — a target that names the operation rather than a place
// (`apt-get install`, `gpg --recv-keys`, a perl/python network module) — is
// off-policy by definition: no allow-list entry can name one. git is judged
// by host instead (Policy.GitHosts), resolving an indicator (a remote name)
// through the repository's config first. Downloaders are served upstream by
// httpMiddleware, so they don't reach here.
func egressGuardMiddleware(p Policy) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			parsed := command.Parse(args)
			egress, networked := parsed.EgressInfo()
			if !networked {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			target := egress.Target
			var allowed bool
			if _, isGit := parsed.Command().(command.Git); isGit {
				allowed = p.AllowsGit(target)
				if !allowed && egress.Kind == command.EgressIndicator { // a remote name: resolve it
					if url := resolveGitRemote(hc.Dir, hc.Env, parsed); url != "" {
						target = target + " = " + url
						allowed = p.AllowsGit(url)
					}
				}
			} else if egress.Kind != command.EgressIndicator {
				allowed = p.AllowsTarget(target) // an indicator stays denied: it names no place
			}
			if !allowed {
				return failf(hc.Stderr, 1, "[sandbox] network egress denied: %s → %s", parsed.Name, target)
			}
			return next(ctx, args)
		}
	}
}

// resolveGitRemote looks up the remote a git invocation names in the
// repository's config (internal/gitconfig), the way git itself does: the URL
// under [remote "NAME"], pushurl first for push. It returns "" when there is
// no repository or no such remote. The repository is the --git-dir flag,
// else $GIT_DIR, else the nearest .git above the working directory (after
// any -C). This is what lets `git clone URL dir; git -C dir fetch origin`
// work when the clone was allowed, while a remote pointed off-list — by
// whatever means — is still denied at the moment it is used.
func resolveGitRemote(cwd string, env expand.Environ, parsed command.ParsedCommand) string {
	name, _ := parsed.Egress()
	for _, c := range parsed.Values("-C") {
		cwd = absJoin(cwd, c)
	}
	gitDir, _ := parsed.FlagValue("--git-dir")
	if gitDir == "" {
		gitDir = env.Get("GIT_DIR").String()
	}
	if gitDir != "" {
		gitDir = absJoin(cwd, gitDir)
	} else {
		gitDir = gitconfig.FindGitDir(cwd)
	}
	if gitDir == "" {
		return ""
	}
	url, pushURL := gitconfig.RemoteURLs(gitDir, name)
	if parsed.Subcommand == "push" && pushURL != "" {
		return pushURL
	}
	return url
}

// absJoin resolves p against base unless it is already absolute.
func absJoin(base, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(base, p)
}

package sandbox

// The in-process network layer. curl/wget are not delegated to host binaries
// (which can reach any URL): httpMiddleware intercepts every command.Downloader,
// takes its parsed Request, and drives a configurable net/http.Client. That
// moves the boundary in-process — the allow-list, redirect policy, timeout,
// size cap, header injection and transport (proxy/TLS/DNS) are all enforced
// here. Other network-capable commands (openssl s_client, ssh, nc, git clone)
// are denied by egressGuardMiddleware using the same Policy.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
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
	AllowedMethods  map[string]bool // HTTP methods a downloader may use
	MaxResponse     int64           // response body cap in bytes
	Timeout         time.Duration   // per-request timeout
	// InjectHeaders are added to every request (e.g. a broker token) so secrets
	// never have to appear in the sandboxed script itself.
	InjectHeaders map[string]string
	// GitHosts are the hosts git may clone/fetch/push to, over any transport
	// (https, ssh, git://, scp-like user@host:path); a subdomain of a listed
	// host counts. Git is not a downloader, so it bypasses the in-process HTTP
	// client — this is the only gate on where it talks to. See AllowsGit.
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
		Timeout:        60 * time.Second,
		GitHosts:       DefaultGitHosts(),
	}
}

// Allows reports whether u may be fetched: some AllowedPrefixes entry matches
// it, and the URL is unambiguous about where it goes.
//
// Two shapes are refused before the list is consulted, because both are ways
// to write a URL that READS as one host and RESOLVES as another — the failure
// mode of every allow-list that compares URLs as text:
//
//   - userinfo. "https://allowed.example@evil.example/x" has the allow-listed
//     name in it, and an HTTP client dials evil.example.
//   - a "." or ".." path segment, in raw or percent-encoded form.
//     "https://host/allowed/../evil" passes any path check and is normalised
//     by the server afterwards.
func (p Policy) Allows(u *url.URL) bool {
	if u == nil || u.User != nil || hasDotSegment(u.Path) {
		return false
	}
	for _, pre := range p.AllowedPrefixes {
		if r, ok := parseURLRule(pre); ok && r.allows(u) {
			return true
		}
	}
	return false
}

// AllowsTarget permits only allow-listed URLs; a raw host:port (openssl/ssh/nc)
// is not a URL, so it is denied.
func (p Policy) AllowsTarget(target string) bool {
	if !strings.Contains(target, "://") {
		return false
	}
	u, err := url.Parse(target)
	return err == nil && p.Allows(u)
}

// Validate reports the AllowedPrefixes entries that are not URL prefixes at
// all — "example.com/x" with no scheme, say. Such an entry matches nothing, so
// a mistyped policy fails closed, which is safe but silent: a caller taking
// the list from a user (the CLI does) should surface it instead.
func (p Policy) Validate() error {
	var bad []string
	for _, pre := range p.AllowedPrefixes {
		if _, ok := parseURLRule(pre); !ok {
			bad = append(bad, strconv.Quote(pre))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("URL allow-list needs a scheme on every entry (e.g. https://host/path); cannot use %s", strings.Join(bad, ", "))
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
	host := gitTargetHost(target)
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

// gitTargetHost extracts the host from a git remote: scheme://[user@]host[:port]/path
// or the scp-like [user@]host:path. "" when the target isn't a remote.
func gitTargetHost(target string) string {
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

// client builds the http.Client with the policy applied. Everything you'd
// normally reach for on a client — Timeout, CheckRedirect, Transport
// (Proxy/TLSClientConfig/DialContext) — is wired here.
func (p Policy) client() *http.Client {
	return &http.Client{
		Timeout: p.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 20 {
				return fmt.Errorf("stopped after 20 redirects")
			}
			if !p.Allows(req.URL) { // re-check the allow-list on every hop
				return fmt.Errorf("redirect to disallowed URL: %s", req.URL)
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			DialContext:       (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			ForceAttemptHTTP2: true,
			// TLSClientConfig: &tls.Config{...} // pin certs / min version here
		},
	}
}

// httpMiddleware serves every command.Downloader in-process; everything else
// falls through to next. root is the sandbox root that a fetch may write into
// (see outputSink); "" leaves the write unconfined.
func httpMiddleware(p Policy, root string) Middleware {
	client := p.client()
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			d, ok := command.Lookup(args[0]).(command.Downloader)
			if !ok {
				return next(ctx, args)
			}
			parsed := command.Parse(args)
			tool := filepath.Base(args[0])
			// A Request carries one URL, but curl takes several and pairs them
			// with successive -o names. Serving only the first would fetch part
			// of what was asked for and say nothing about the rest, so refuse
			// the whole invocation and name what was dropped.
			if urls := urlOperands(parsed); len(urls) > 1 {
				return failf(interp.HandlerCtx(ctx).Stderr, 2,
					"%s: [sandbox] one URL per invocation, got %d: %s", tool, len(urls), strings.Join(urls, " "))
			}
			return runDownloader(ctx, client, p, root, tool, d.Request(parsed))
		}
	}
}

// urlOperands lists the operands that carry a scheme, i.e. the URLs a fetcher
// was asked for. Operands without one (a bare host, a stray value) are left
// out: the downloader's own parse decides what those mean.
func urlOperands(p command.ParsedCommand) []string {
	var urls []string
	for _, o := range p.Operands {
		if strings.Contains(o, "://") {
			urls = append(urls, o)
		}
	}
	return urls
}

// runDownloader performs one fetch under the policy, emulating the tool's exit
// codes (curl's: 2 usage, 3 bad URL, 6 unresolvable, 7 connect, 22 HTTP, 23 write).
func runDownloader(ctx context.Context, client *http.Client, p Policy, root, tool string, req command.Request) error {
	hc := interp.HandlerCtx(ctx)
	if req.URL == "" {
		return failf(hc.Stderr, 2, "%s: no URL specified", tool)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return failf(hc.Stderr, 3, "%s: bad URL %q: %v", tool, req.URL, err)
	}
	if !p.Allows(u) {
		return failf(hc.Stderr, 6, "%s: [sandbox] URL not in allow-list: %s", tool, u)
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if req.Head {
		method = "HEAD"
	}
	if !p.AllowedMethods[method] {
		return failf(hc.Stderr, 6, "%s: [sandbox] method not allowed: %s", tool, method)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return failf(hc.Stderr, 2, "%s: %v", tool, err)
	}
	for k, vs := range req.Headers {
		for _, v := range vs {
			httpReq.Header.Add(k, v)
		}
	}
	for k, v := range p.InjectHeaders { // policy-injected headers win
		httpReq.Header.Set(k, v)
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", tool+"-sandbox")
	}

	if !req.Follow { // curl without -L returns the 3xx itself
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &c
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return failf(hc.Stderr, 7, "%s: %v", tool, err)
	}
	defer resp.Body.Close()
	if req.FailOnHTTP && resp.StatusCode >= 400 {
		return failf(hc.Stderr, 22, "%s: The requested URL returned error: %d", tool, resp.StatusCode)
	}

	out, err := outputSink(hc, root, req, u)
	if err != nil {
		return failf(hc.Stderr, 23, "%s: %v", tool, err)
	}
	if req.Head {
		fmt.Fprintf(out, "%s %s\r\n", resp.Proto, resp.Status)
		_ = resp.Header.Write(out)
		return out.Close()
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, p.MaxResponse+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return failf(hc.Stderr, 23, "%s: %v", tool, err)
	}
	if n > p.MaxResponse {
		return failf(hc.Stderr, 23, "%s: response exceeded %d bytes", tool, p.MaxResponse)
	}
	if req.WriteOut != "" {
		io.WriteString(hc.Stdout, writeOut(req.WriteOut, resp))
	}
	return nil
}

// writeOut expands the curl -w variables installers use: %{http_code},
// %{url_effective} (the URL after redirects) and %{redirect_url} (where an
// unfollowed 3xx points — warp resolves its versioned artifact URL this way
// instead of letting curl follow the 302). Unknown variables expand empty.
func writeOut(format string, resp *http.Response) string {
	return writeOutRE.ReplaceAllStringFunc(format, func(v string) string {
		switch v {
		case "%{http_code}", "%{response_code}":
			return strconv.Itoa(resp.StatusCode)
		case "%{url_effective}":
			return resp.Request.URL.String()
		case "%{redirect_url}":
			if loc, err := resp.Location(); err == nil && resp.StatusCode/100 == 3 {
				return loc.String() // resolved against the request URL, as curl does
			}
			return ""
		case "%{content_type}":
			return resp.Header.Get("Content-Type")
		case "%{size_download}":
			return strconv.FormatInt(resp.ContentLength, 10)
		}
		return ""
	})
}

var writeOutRE = regexp.MustCompile(`%\{[a-z_]+\}`)

// outputSink picks where the body goes: -o FILE, -O remote-name, or stdout.
// Relative paths resolve against the script's working directory.
//
// This is the one write the sandbox performs ITSELF rather than delegating to
// a host binary, and so the one it can confine: with a root set, a target
// outside it is refused. Everything else about the filesystem here is
// convention (HOME and TMPDIR point inside the root); this is not, because
// `curl -o ~/.zshrc` from an allow-listed URL would otherwise be a write the
// sandbox carried out on the script's behalf, past every guard it has.
func outputSink(hc interp.HandlerContext, root string, req command.Request, u *url.URL) (io.WriteCloser, error) {
	target := req.Output
	if req.RemoteName && target == "" {
		target = path.Base(u.Path)
	}
	if target == "" || target == "-" {
		return nopCloser{hc.Stdout}, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(hc.Dir, target)
	}
	if target == os.DevNull { // `curl -o /dev/null` is a fetch with no output
		return nopCloser{io.Discard}, nil
	}
	if root != "" && !withinRoot(root, target) {
		return nil, fmt.Errorf("[sandbox] refusing to write outside the sandbox root: %s", target)
	}
	f, err := os.Create(target)
	if err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", target, err)
	}
	return f, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

// egressGuardMiddleware denies any network-capable command whose target isn't
// allow-listed — openssl s_client, ssh, nc, git clone — from ONE place, using
// the parser's Egress indicator. git is judged by host (Policy.GitHosts),
// everything else by the URL prefix list. Downloaders are served upstream by
// httpMiddleware, so they don't reach here.
func egressGuardMiddleware(p Policy) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			parsed := command.Parse(args)
			target, networked := parsed.Egress()
			if !networked {
				return next(ctx, args)
			}
			hc := interp.HandlerCtx(ctx)
			allowed := p.AllowsTarget(target)
			if _, isGit := parsed.Command().(command.Git); isGit {
				allowed = p.AllowsGit(target)
				if !allowed && gitTargetHost(target) == "" { // a remote name: resolve it
					if url := resolveGitRemote(hc.Dir, hc.Env, parsed); url != "" {
						target = target + " = " + url
						allowed = p.AllowsGit(url)
					}
				}
			}
			if !allowed {
				return failf(hc.Stderr, 1, "[sandbox] network egress denied: %s → %s", parsed.Name, target)
			}
			return next(ctx, args)
		}
	}
}

// resolveGitRemote looks up the remote a git invocation names in the
// repository's config, the way git itself does: the URL under [remote "NAME"]
// (pushurl first for push). It returns "" when there is no repository or no
// such remote. The repository is the --git-dir flag, else $GIT_DIR, else the
// nearest .git above the working directory (after any -C); a .git file
// (worktree, submodule) is followed to the directory it points at. This is what
// lets `git clone URL dir; git -C dir fetch origin` work when the clone was
// allowed, while a remote pointed off-list — by whatever means — is still
// denied at the moment it is used.
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
		gitDir = findGitDir(cwd)
	}
	if gitDir == "" {
		return ""
	}
	if fi, err := os.Stat(gitDir); err == nil && !fi.IsDir() { // "gitdir: PATH"
		gitDir = followGitFile(gitDir)
	}
	data, err := os.ReadFile(filepath.Join(gitDir, "config"))
	if err != nil {
		return ""
	}
	urls := gitRemoteURLs(string(data), name)
	if parsed.Subcommand == "push" && urls["pushurl"] != "" {
		return urls["pushurl"]
	}
	return urls["url"]
}

// findGitDir walks up from dir to the nearest .git entry (directory or file).
func findGitDir(dir string) string {
	for {
		g := filepath.Join(dir, ".git")
		if _, err := os.Lstat(g); err == nil {
			return g
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// followGitFile reads a `gitdir: PATH` pointer file; "" if it isn't one.
func followGitFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	target, ok := strings.CutPrefix(strings.TrimSpace(string(b)), "gitdir:")
	if !ok {
		return ""
	}
	return absJoin(filepath.Dir(p), strings.TrimSpace(target))
}

// gitRemoteURLs reads the url/pushurl keys of [remote "name"] from a git config.
// Only the syntax git writes itself is understood — `[section "sub"]` headers and
// `key = value` lines — which is all that clone/remote produce.
func gitRemoteURLs(config, name string) map[string]string {
	urls := map[string]string{}
	inRemote := false
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inRemote = line == `[remote "`+name+`"]`
			continue
		}
		if !inRemote {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			urls[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return urls
}

// absJoin resolves p against base unless it is already absolute.
func absJoin(base, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(base, p)
}

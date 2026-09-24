package tool

// curl and wget run through a policy-configured HTTP client rather than host
// binaries. The surrounding sandbox owns policy construction; this package
// owns command parsing, request execution, and confined input/output handling.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// DownloaderConfig supplies the network and filesystem decisions owned by
// the sandbox without coupling tool implementations back to package sandbox.
type DownloaderConfig struct {
	Client    *http.Client
	AllowURL  func(*url.URL) bool
	AllowPath func(string) bool
	// AllowMethod gates HTTP methods; nil denies every method, the same
	// polarity as AllowURL.
	AllowMethod func(method string) bool
	// AllowMIME, when non-nil, gates response bodies by media type: the
	// declared Content-Type must satisfy it and the sniffed first bytes must
	// not contradict it (see checkMIME). nil means no MIME restriction —
	// note the opposite polarity from AllowURL and AllowMethod, where nil
	// denies. The response's types are observed into the ResponseNote either
	// way.
	AllowMIME     func(mediaType string) bool
	MaxResponse   int64
	MaxRequest    int64
	InjectHeaders map[string]string
}

// Downloaders serves curl and wget in-process; all other commands fall
// through to next.
func Downloaders(cfg DownloaderConfig) func(interp.ExecHandlerFunc) interp.ExecHandlerFunc {
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
			name := filepath.Base(args[0])
			hc := interp.HandlerCtx(ctx)
			if parsed.HasFlag("--version", "-V") {
				_, _ = io.WriteString(hc.Stdout, versionBanner(name))
				return nil
			}
			if parsed.HasFlag("--help", "-h") {
				_, _ = io.WriteString(hc.Stdout, helpText(name))
				return nil
			}
			if urls := append(urlOperands(parsed), parsed.Values("--url")...); len(urls) > 1 {
				return Failf(hc.Stderr, 2,
					"%s: [sandbox] one URL per invocation, got %d: %s", name, len(urls), strings.Join(urls, " "))
			}
			return runDownloader(ctx, cfg, name, d.Request(parsed))
		}
	}
}

func urlOperands(p command.ParsedCommand) []string {
	var urls []string
	for _, operand := range p.Operands {
		if strings.Contains(operand, "://") {
			urls = append(urls, operand)
		}
	}
	return urls
}

func runDownloader(ctx context.Context, cfg DownloaderConfig, name string, req command.Request) error {
	hc := interp.HandlerCtx(ctx)
	if req.URL == "" {
		return Failf(hc.Stderr, 2, "%s: no URL specified", name)
	}
	u, err := url.Parse(req.URL)
	if err != nil {
		return Failf(hc.Stderr, 3, "%s: bad URL %q: %v", name, req.URL, err)
	}
	if cfg.AllowURL == nil || !cfg.AllowURL(u) {
		return Failf(hc.Stderr, 6, "%s: [sandbox] URL not in allow-list: %s", name, u)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	if req.Head {
		method = http.MethodHead
	}
	if cfg.AllowMethod == nil || !cfg.AllowMethod(method) {
		return Failf(hc.Stderr, 6, "%s: [sandbox] method not allowed: %s", name, method)
	}

	body, err := requestBody(hc, cfg, req.Body)
	if err != nil {
		return Failf(hc.Stderr, 26, "%s: %v", name, err)
	}
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if err != nil {
		return Failf(hc.Stderr, 2, "%s: %v", name, err)
	}
	for key, values := range req.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}
	for key, value := range cfg.InjectHeaders {
		httpReq.Header.Set(key, value)
	}
	if len(req.Body) > 0 && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if httpReq.Header.Get("User-Agent") == "" {
		httpReq.Header.Set("User-Agent", name+"-sandbox")
	}

	client := cfg.Client
	if client == nil {
		return Failf(hc.Stderr, 7, "%s: HTTP client is unavailable", name)
	}
	if !req.Follow {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copy
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return Failf(hc.Stderr, 7, "%s: %v", name, err)
	}
	defer resp.Body.Close()
	note := ResponseNoteFrom(ctx)
	if note != nil {
		note.Via = hopURLs(resp)
	}
	if req.FailOnHTTP && resp.StatusCode >= 400 {
		return Failf(hc.Stderr, 22, "%s: The requested URL returned error: %d", name, resp.StatusCode)
	}

	var respBody io.Reader = resp.Body
	if !req.Head {
		br := bufio.NewReaderSize(resp.Body, sniffLen)
		respBody = br
		// An empty body delivers nothing to the script, so there is nothing
		// to observe or gate — this also spares Content-Type-less 204/304
		// responses from the missing-Content-Type denial.
		if peek, _ := br.Peek(sniffLen); len(peek) > 0 {
			declared, sniffed := classifyMIME(resp.Header.Get("Content-Type"), peek)
			if note != nil {
				note.ContentType, note.Sniffed = declared, sniffed
			}
			if cfg.AllowMIME != nil {
				if _, _, mimeErr := checkMIME(cfg.AllowMIME, resp.Header.Get("Content-Type"), peek); mimeErr != nil {
					return Failf(hc.Stderr, 6, "%s: [sandbox] %v", name, mimeErr)
				}
			}
		}
	}

	out, err := outputSink(hc, cfg, req, u)
	if err != nil {
		return Failf(hc.Stderr, 23, "%s: %v", name, err)
	}
	if req.Head {
		fmt.Fprintf(out, "%s %s\r\n", resp.Proto, resp.Status)
		_ = resp.Header.Write(out)
		return out.Close()
	}
	n, err := io.Copy(out, io.LimitReader(respBody, cfg.MaxResponse+1))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Failf(hc.Stderr, 23, "%s: %v", name, err)
	}
	if n > cfg.MaxResponse {
		return Failf(hc.Stderr, 23, "%s: response exceeded %d bytes", name, cfg.MaxResponse)
	}
	if req.WriteOut != "" {
		_, _ = io.WriteString(hc.Stdout, writeOut(req.WriteOut, resp))
	}
	return nil
}

// sniffLen is how many leading body bytes http.DetectContentType examines.
const sniffLen = 512

// classifyMIME reports the declared media type of a response (lower-case,
// parameters stripped; "" when the header is missing or unparseable) and the
// sniffed type of its first body bytes — http.DetectContentType sharpened by
// refineSniff, so an octet-stream body reads as the tar/xz/executable/… it
// actually is, and a shebanged script as its interpreter's type.
func classifyMIME(contentType string, peek []byte) (declared, sniffed string) {
	sniffed, _, _ = mime.ParseMediaType(http.DetectContentType(peek))
	sniffed = refineSniff(sniffed, peek)
	declared, _, err := mime.ParseMediaType(strings.ToLower(contentType))
	if contentType == "" || err != nil {
		return "", sniffed
	}
	return declared, sniffed
}

// checkMIME applies the MIME allow-list to a non-empty response body: the
// declared Content-Type must parse and be allowed, and the sniffed type of
// the first bytes must not contradict it. It returns the declared and
// sniffed media types (lower-case, parameters stripped) for the audit trail
// even when it denies.
func checkMIME(allow func(string) bool, contentType string, peek []byte) (declared, sniffed string, err error) {
	declared, sniffed = classifyMIME(contentType, peek)
	if contentType == "" {
		return "", sniffed, errors.New("response has no Content-Type and a mime-types allow-list is set")
	}
	if declared == "" {
		return "", sniffed, fmt.Errorf("unparseable response Content-Type %q", contentType)
	}
	if !allow(declared) {
		return declared, sniffed, fmt.Errorf("response Content-Type %q not in mime-types allow-list", declared)
	}
	if !sniffAllowed(allow, declared, sniffed) {
		return declared, sniffed, fmt.Errorf("response body sniffs as %q (declared %q) — not in mime-types allow-list", sniffed, declared)
	}
	return declared, sniffed, nil
}

// hopURLs walks the redirect chain net/http leaves on a response —
// resp.Request is the FINAL request; each earlier hop hangs off
// Request.Response — and returns the full URL of every hop, initial request
// first, deduplicated preserving first occurrence. Consumers derive what
// they need: the audit log renders hosts, the manifest profiler scopes
// project-shaped URLs by path.
func hopURLs(resp *http.Response) []string {
	var reversed []string
	for r := resp; r != nil && r.Request != nil; r = r.Request.Response {
		if r.Request.URL != nil {
			reversed = append(reversed, r.Request.URL.String())
		}
	}
	var urls []string
	seen := map[string]bool{}
	for i := len(reversed) - 1; i >= 0; i-- {
		if !seen[reversed[i]] {
			seen[reversed[i]] = true
			urls = append(urls, reversed[i])
		}
	}
	return urls
}

// sniffAllowed reports whether the sniffed type is acceptable: allowed
// itself, indistinct (octet-stream is DetectContentType's fallback, and a
// binary type refineSniff derived from it counts the same — the refinement
// is for the audit trail, not new denials), a known alias of an allowed
// type, or plain text — including a refined script type — under a declared
// text-ish type (shell scripts, JSON and YAML all sniff as text/plain).
func sniffAllowed(allow func(string) bool, declared, sniffed string) bool {
	if allow(sniffed) || sniffed == "application/octet-stream" || binarySniffs[sniffed] {
		return true
	}
	for _, alias := range sniffAliases[sniffed] {
		if allow(alias) {
			return true
		}
	}
	return (sniffed == "text/plain" || scriptSniffs[sniffed]) && textish(declared)
}

// sniffAliases maps what http.DetectContentType says to what servers
// commonly declare for the same bytes. Grow it as coarse sniffs surface.
var sniffAliases = map[string][]string{
	"application/x-gzip":           {"application/gzip", "application/octet-stream"},
	"application/zip":              {"application/x-zip-compressed", "application/octet-stream"},
	"application/x-rar-compressed": {"application/octet-stream"},
	"application/wasm":             {"application/octet-stream"},
	"text/xml":                     {"application/xml"},
}

// textish reports whether a declared media type plausibly ships as what
// DetectContentType calls text/plain.
func textish(declared string) bool {
	if strings.HasPrefix(declared, "text/") ||
		strings.HasSuffix(declared, "+json") || strings.HasSuffix(declared, "+xml") {
		return true
	}
	switch declared {
	case "application/json", "application/javascript", "application/x-sh",
		"application/x-shellscript", "application/x-csh", "application/xml",
		"application/yaml", "application/x-yaml", "application/toml":
		return true
	}
	return false
}

func requestBody(hc interp.HandlerContext, cfg DownloaderConfig, parts []command.RequestBodyPart) ([]byte, error) {
	var out bytes.Buffer
	for i, part := range parts {
		var data []byte
		if part.File {
			if part.Value == "-" {
				if hc.Stdin == nil {
					return nil, fmt.Errorf("request body stdin is unavailable")
				}
				b, err := io.ReadAll(io.LimitReader(hc.Stdin, cfg.MaxRequest+1))
				if err != nil {
					return nil, fmt.Errorf("reading request body from stdin: %w", err)
				}
				data = b
			} else {
				name := part.Value
				if !filepath.IsAbs(name) {
					name = filepath.Join(hc.Dir, name)
				}
				if cfg.AllowPath != nil && !cfg.AllowPath(name) {
					return nil, fmt.Errorf("[sandbox] refusing to read request body outside the sandbox root: %s", name)
				}
				file, err := os.Open(name)
				if err != nil {
					return nil, fmt.Errorf("reading request body %s: %w", name, err)
				}
				data, err = io.ReadAll(io.LimitReader(file, cfg.MaxRequest+1))
				_ = file.Close()
				if err != nil {
					return nil, fmt.Errorf("reading request body %s: %w", name, err)
				}
			}
			if part.StripNewlines {
				data = bytes.ReplaceAll(data, []byte{'\r'}, nil)
				data = bytes.ReplaceAll(data, []byte{'\n'}, nil)
			}
		} else {
			data = []byte(part.Value)
		}
		if part.URLEncode {
			data = []byte(strings.ReplaceAll(url.QueryEscape(string(data)), "+", "%20"))
		}
		if i > 0 {
			out.WriteByte('&')
		}
		out.WriteString(part.Prefix)
		out.Write(data)
		if int64(out.Len()) > cfg.MaxRequest {
			return nil, fmt.Errorf("request body exceeded %d bytes", cfg.MaxRequest)
		}
	}
	return out.Bytes(), nil
}

func writeOut(format string, resp *http.Response) string {
	return writeOutRE.ReplaceAllStringFunc(format, func(value string) string {
		switch value {
		case "%{http_code}", "%{response_code}":
			return strconv.Itoa(resp.StatusCode)
		case "%{url_effective}":
			return resp.Request.URL.String()
		case "%{redirect_url}":
			if location, err := resp.Location(); err == nil && resp.StatusCode/100 == 3 {
				return location.String()
			}
		case "%{content_type}":
			return resp.Header.Get("Content-Type")
		case "%{size_download}":
			return strconv.FormatInt(resp.ContentLength, 10)
		}
		return ""
	})
}

var writeOutRE = regexp.MustCompile(`%\{[a-z_]+\}`)

func outputSink(hc interp.HandlerContext, cfg DownloaderConfig, req command.Request, u *url.URL) (io.WriteCloser, error) {
	target := req.Output
	if req.RemoteName && target == "" {
		target = path.Base(u.Path)
		if target == "" || target == "." || target == "/" || strings.HasSuffix(u.Path, "/") {
			target = "index.html" // wget's default for a URL with no filename
		}
	}
	if target == "" || target == "-" {
		return nopCloser{hc.Stdout}, nil
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(hc.Dir, target)
	}
	if target == os.DevNull {
		return nopCloser{io.Discard}, nil
	}
	if cfg.AllowPath != nil && !cfg.AllowPath(target) {
		return nil, fmt.Errorf("[sandbox] refusing to write outside the sandbox root: %s", target)
	}
	file, err := os.Create(target)
	if err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", target, err)
	}
	return file, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

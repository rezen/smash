package tool

// curl and wget run through a policy-configured HTTP client rather than host
// binaries. The surrounding sandbox owns policy construction; this package
// owns command parsing, request execution, and confined input/output handling.

import (
	"bytes"
	"context"
	"fmt"
	"io"
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
	Client         *http.Client
	AllowURL       func(*url.URL) bool
	AllowPath      func(string) bool
	AllowedMethods map[string]bool
	MaxResponse    int64
	MaxRequest     int64
	InjectHeaders  map[string]string
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
			if urls := urlOperands(parsed); len(urls) > 1 {
				return Failf(interp.HandlerCtx(ctx).Stderr, 2,
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
	if !cfg.AllowedMethods[method] {
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
	if req.FailOnHTTP && resp.StatusCode >= 400 {
		return Failf(hc.Stderr, 22, "%s: The requested URL returned error: %d", name, resp.StatusCode)
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
	n, err := io.Copy(out, io.LimitReader(resp.Body, cfg.MaxResponse+1))
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

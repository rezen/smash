package tool

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// allowOnly builds the allow func the sandbox would install for a fixed list
// of bare media types.
func allowOnly(types ...string) func(string) bool {
	return func(mt string) bool {
		for _, t := range types {
			if t == mt {
				return true
			}
		}
		return false
	}
}

func TestCheckMIME(t *testing.T) {
	html := []byte("<!DOCTYPE html><html><body>error</body></html>")
	gzip := []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03binary")
	script := []byte("#!/bin/sh\necho hi\n")
	for _, tc := range []struct {
		name        string
		allow       func(string) bool
		contentType string
		peek        []byte
		wantErr     string // "" means allowed
	}{
		{"declared and sniffed agree", allowOnly("text/html"), "text/html", html, ""},
		{"parameters are stripped", allowOnly("text/plain"), "text/plain; charset=utf-8", script, ""},
		{"case-insensitive declaration", allowOnly("text/plain"), "Text/PLAIN", script, ""},
		{"gzip sniff under its common declared name", allowOnly("application/gzip"), "application/gzip", gzip, ""},
		{"octet-stream declaration admits gzip bytes", allowOnly("application/octet-stream"), "application/octet-stream", gzip, ""},
		{"shell script sniffs text/plain under a text-ish type", allowOnly("text/x-shellscript"), "text/x-shellscript", script, ""},
		{"json declaration over plain-text bytes", allowOnly("application/json"), "application/json", []byte(`{"a":1}`), ""},
		{"missing Content-Type", allowOnly("text/html"), "", html, "no Content-Type"},
		{"unparseable Content-Type", allowOnly("text/html"), ";;", html, "unparseable"},
		{"declared type off-list", allowOnly("application/gzip"), "text/html", html, `"text/html" not in mime-types`},
		{"mislabeled body: html under an archive declaration", allowOnly("application/gzip"), "application/gzip", html, `sniffs as "text/html"`},
		{"empty allow-list denies", allowOnly(), "text/html", html, "not in mime-types"},
	} {
		_, _, err := checkMIME(tc.allow, tc.contentType, tc.peek)
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("%s: unexpected denial: %v", tc.name, err)
			}
		} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: err = %v, want it to contain %q", tc.name, err, tc.wantErr)
		}
	}
}

func TestClassifyMIME(t *testing.T) {
	html := []byte("<!DOCTYPE html><html>")
	for _, tc := range []struct {
		contentType       string
		peek              []byte
		declared, sniffed string
	}{
		{"application/gzip", html, "application/gzip", "text/html"},
		{"Text/PLAIN; charset=utf-8", []byte("hi"), "text/plain", "text/plain"},
		{"", html, "", "text/html"},
		{";;", html, "", "text/html"},
	} {
		declared, sniffed := classifyMIME(tc.contentType, tc.peek)
		if declared != tc.declared || sniffed != tc.sniffed {
			t.Errorf("classifyMIME(%q) = %q/%q, want %q/%q", tc.contentType, declared, sniffed, tc.declared, tc.sniffed)
		}
	}
}

// TestHopURLs: net/http leaves the redirect chain hanging off the final
// response — resp.Request is the last request, each earlier hop reachable
// through Request.Response. The walk must come back chronological, as full
// URLs (the manifest profiler scopes project-shaped hops by path), deduped
// by exact URL.
func TestHopURLs(t *testing.T) {
	mkURL := func(raw string) *url.URL {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	first := &http.Request{URL: mkURL("https://github.com/o/r/releases/download/v1/x")}
	firstResp := &http.Response{Request: first}
	second := &http.Request{URL: mkURL("https://objects.githubusercontent.com/asset"), Response: firstResp}
	secondResp := &http.Response{Request: second}
	// A loop back to an already-seen URL dedupes; a different path on the
	// same host does not.
	third := &http.Request{URL: mkURL("https://objects.githubusercontent.com/asset"), Response: secondResp}
	final := &http.Response{Request: third}

	got := strings.Join(hopURLs(final), ",")
	want := "https://github.com/o/r/releases/download/v1/x,https://objects.githubusercontent.com/asset"
	if got != want {
		t.Errorf("hopURLs = %s, want %s", got, want)
	}
	single := &http.Response{Request: first}
	if got := strings.Join(hopURLs(single), ","); got != "https://github.com/o/r/releases/download/v1/x" {
		t.Errorf("hopURLs(no redirects) = %s", got)
	}
}

// TestCheckMIMEReportsTypes: the audit trail needs both types even when the
// check denies.
func TestCheckMIMEReportsTypes(t *testing.T) {
	declared, sniffed, err := checkMIME(allowOnly("application/gzip"), "application/gzip", []byte("<!DOCTYPE html>"))
	if err == nil {
		t.Fatal("a mislabeled body should be denied")
	}
	if declared != "application/gzip" || sniffed != "text/html" {
		t.Errorf("declared=%q sniffed=%q, want application/gzip / text/html", declared, sniffed)
	}
}

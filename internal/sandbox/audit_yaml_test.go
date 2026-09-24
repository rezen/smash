package sandbox

// TextAuditor hand-rolls its YAML (yamlenc.Scalar for quoting, plus its own
// record/capture rendering) so it can stream one record at a time with
// stable key order. These tests back the whole emitter with a real parser:
// everything it writes must be a YAML stream gopkg.in/yaml.v3 reads back,
// and every hostile value must come back as the SAME STRING — never silently
// as a bool, number, null, or a broken document. yamlenc has its own
// unit-level round-trip test; this one covers the assembled records.

import (
	"bytes"
	"errors"
	"testing"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/rezen/smash/internal/command"
)

// hostileScalars is the gauntlet: indicator-leading values, flow characters,
// mapping/comment look-alikes, every null/bool spelling, number shapes,
// whitespace edges, control characters and non-ASCII. All valid UTF-8, so
// each must round-trip byte-identically as a string.
var hostileScalars = []string{
	"plain", "",
	"- leading dash", "? question", ": colon", "# hash", "@ at", "` tick",
	"&anchor", "*alias", "!tag", "|literal", ">folded", "%directive",
	"'single'", `"double"`, "a, b", "[seq]", "{map}", "a: b", "a #comment",
	"trailing:",
	"~", "null", "Null", "true", "False", "yes", "no", "on", "off", "y", "N",
	".inf", "-.Inf", "+.INF", ".NaN",
	"600", "0x1f", "0o17", "1e3", "1_000", "1:30", "+1", "-1", ".5", "1.2.3",
	"2026-09-24", "=",
	// a query-string URL: "?" ends a flow-context plain scalar in go-yaml,
	// which corrupted resources: [...] lists until yamlenc learned to quote it
	"https://example.com/tool?arch=arm64&os=linux",
	" leading space", "trailing space ", "\ttab", "line\nbreak", "cr\rlf",
	"nul\x00byte", "unit\x1fsep", "del\x7f", "line sep",
	"emoji 🚀", "combining é",
}

func TestTextAuditorEmitsValidYAML(t *testing.T) {
	var buf bytes.Buffer
	a := TextAuditor(&buf)
	oa := a.(OpenAuditor)
	for _, s := range hostileScalars {
		a.Audit(AuditRecord{
			Name:      s,
			Command:   s,
			Reason:    s,
			Wrappers:  []string{s},
			Resources: []command.Resource{{Kind: "path", Action: "write", Value: s}},
			Stdin:     Capture{Data: []byte(s), Total: int64(len(s))},
		})
		oa.AuditOpen(OpenRecord{Path: s, Op: OpenWrite, Err: errors.New(s)})
	}

	var docs []map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &docs); err != nil {
		t.Fatalf("audit stream is not parseable YAML: %v\nstream:\n%s", err, buf.String())
	}
	if want := 2 * len(hostileScalars); len(docs) != want {
		t.Fatalf("parsed %d records, want %d", len(docs), want)
	}
	for i, s := range hostileScalars {
		rec := docs[2*i]
		keys := []string{"name", "command", "reason"}
		if s == "" {
			keys = keys[:2] // an empty reason is intentionally not emitted
		}
		for _, key := range keys {
			got, ok := rec[key].(string)
			if !ok {
				t.Errorf("record %q key %s: parsed as %T (%#v), must stay a string", s, key, rec[key], rec[key])
				continue
			}
			if got != s {
				t.Errorf("record key %s: %q round-tripped as %q", key, s, got)
			}
		}
		if !utf8.ValidString(s) || len(s) == 0 {
			continue
		}
		stdin, ok := rec["stdin"].(map[string]any)
		if !ok {
			t.Errorf("record %q: stdin capture missing or mis-shaped: %#v", s, rec["stdin"])
			continue
		}
		if got, _ := stdin["data"].(string); got != s {
			t.Errorf("stdin capture: %q round-tripped as %q", s, got)
		}
	}
}

// TestTextAuditorInvalidUTF8StillParses: raw non-UTF-8 bytes cannot survive a
// YAML parser byte-identically — YAML's \xNN is a code-point escape while
// Go's is a byte escape, so a lone 0xff comes back as U+00FF. The contract
// for binary garbage is therefore weaker and this is it: the stream must
// still PARSE, with the data recoverable under the Go-quoting convention.
func TestTextAuditorInvalidUTF8StillParses(t *testing.T) {
	var buf bytes.Buffer
	a := TextAuditor(&buf)
	a.Audit(AuditRecord{
		Name:   "x\xff\xfe",
		Stdout: Capture{Data: []byte{0xff, 0x00, 0xfe}, Total: 3},
	})
	var docs []map[string]any
	if err := yaml.Unmarshal(buf.Bytes(), &docs); err != nil {
		t.Fatalf("stream with invalid UTF-8 does not parse: %v\nstream:\n%s", err, buf.String())
	}
	if len(docs) != 1 {
		t.Fatalf("parsed %d records, want 1", len(docs))
	}
}

// TestTextAuditorParamsTagParses: typed params render as a local-tagged flow
// mapping (`!CurlParams {…}`). The tag must not break parsing, and the node
// under it must still be a mapping with the redacted values.
func TestTextAuditorParamsTagParses(t *testing.T) {
	var buf bytes.Buffer
	a := TextAuditor(&buf)
	p := command.Parse([]string{"curl", "-fsSL", "-H", "Authorization: Bearer sekrit", "https://example.com/a", "-o", "out"})
	a.Audit(AuditRecord{Name: "curl", Command: p.TypedParams().String(), Params: command.Redact(p.TypedParams())})

	var root yaml.Node
	if err := yaml.Unmarshal(buf.Bytes(), &root); err != nil {
		t.Fatalf("record with params does not parse: %v\nstream:\n%s", err, buf.String())
	}
	seq := root.Content[0]
	if seq.Kind != yaml.SequenceNode || len(seq.Content) != 1 {
		t.Fatalf("stream did not parse as a one-item sequence: kind %v", seq.Kind)
	}
	var params *yaml.Node
	rec := seq.Content[0]
	for i := 0; i+1 < len(rec.Content); i += 2 {
		if rec.Content[i].Value == "params" {
			params = rec.Content[i+1]
		}
	}
	if params == nil {
		t.Fatalf("no params key in:\n%s", buf.String())
	}
	if params.Kind != yaml.MappingNode || params.Tag != "!CurlParams" {
		t.Errorf("params node: kind %v tag %q, want a !CurlParams mapping", params.Kind, params.Tag)
	}
	if s := buf.String(); !bytes.Contains(buf.Bytes(), []byte(command.Redacted)) {
		t.Errorf("secret header value not redacted in:\n%s", s)
	}
}

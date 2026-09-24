package yamlenc

// The end-to-end guarantee (a whole audit stream parses and round-trips)
// lives in sandbox's TestTextAuditorEmitsValidYAML. This test checks the
// same property at the unit level, in BOTH contexts a scalar is emitted in:
// as a block mapping value and inside a flow sequence.

import (
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestScalarRoundTripsThroughAParser(t *testing.T) {
	cases := []string{
		"plain", "",
		"- leading dash", "? question", "a: b", "a #comment", "trailing:",
		"a, b", "[seq]", "{map}", "&anchor", "*alias", "!tag", "%directive",
		"~", "null", "True", "yes", "n", ".inf", ".NaN",
		"600", "0x1f", "1e3", "1:30", "-1", ".5", "2026-09-24",
		" leading", "trailing ", "line\nbreak", "nul\x00byte", "del\x7f",
		"https://example.com/tool?arch=arm64&os=linux",
		"emoji 🚀",
	}
	for _, s := range cases {
		for context, doc := range map[string]string{
			"block": "k: " + Scalar(s) + "\n",
			"flow":  "k: [" + Scalar(s) + "]\n",
		} {
			var m map[string]any
			if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
				t.Errorf("Scalar(%q) in %s context does not parse: %v\ndoc: %s", s, context, err, doc)
				continue
			}
			v := m["k"]
			if context == "flow" {
				seq, ok := v.([]any)
				if !ok || len(seq) != 1 {
					t.Errorf("Scalar(%q) in flow context parsed as %#v", s, v)
					continue
				}
				v = seq[0]
			}
			got, ok := v.(string)
			if !ok {
				t.Errorf("Scalar(%q) in %s context parsed as %T (%#v), must stay a string", s, context, v, v)
				continue
			}
			if got != s {
				t.Errorf("Scalar(%q) in %s context round-tripped as %q", s, context, got)
			}
		}
	}
	// Non-UTF-8 input must still parse; byte-identity is impossible in YAML
	// (its \xNN escapes are code points, Go's are bytes).
	doc := fmt.Sprintf("k: %s\n", Scalar("x\xff\xfe"))
	var m map[string]any
	if err := yaml.Unmarshal([]byte(doc), &m); err != nil {
		t.Errorf("Scalar of invalid UTF-8 does not parse: %v\ndoc: %s", err, doc)
	}
}

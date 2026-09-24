// Package yamlenc renders Go strings as YAML scalars a parser reads back
// byte-identically. It exists because the audit log is streamed one record
// at a time with stable key order — a shape yaml.Marshal does not produce —
// so scalars are quoted by rule instead. Quoting is decided for flow context
// (the stricter one), so the same rule serves block values, sequence items
// and mapping values alike.
package yamlenc

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scalar renders s as a YAML scalar: plain when a parser would read it back
// unchanged as a string, otherwise double-quoted. Go's quoted form is valid
// YAML: both use \n, \t, \", \\, \xNN, \uNNNN and \UNNNNNNNN.
func Scalar(s string) string {
	if s == "" || plainWouldMisread(s) {
		return strconv.Quote(s)
	}
	return s
}

// plainWouldMisread reports whether a plain (unquoted) scalar carrying s
// would be read back as anything other than this exact string. Each predicate
// names one way that can happen; double-quoting is the answer to all of them.
func plainWouldMisread(s string) bool {
	return !utf8.ValidString(s) || // strconv.Quote escapes what plain can't carry
		trimsDifferently(s) ||
		startsWithIndicator(s) ||
		containsFlowIndicator(s) ||
		readsAsMappingOrComment(s) ||
		containsNonPrintable(s) ||
		readsAsNullBoolOrFloat(s) ||
		readsAsNumber(s)
}

// trimsDifferently: a plain scalar sheds leading and trailing whitespace, so
// a value with either would come back shortened.
func trimsDifferently(s string) bool { return strings.TrimSpace(s) != s }

// startsWithIndicator: indicator characters cannot begin a plain scalar —
// "- x" is a sequence item, "&x" an anchor, "!x" a tag, and so on.
func startsWithIndicator(s string) bool {
	return s != "" && strings.ContainsAny(s[:1], "-?:,[]{}#&*!|>'\"%@`")
}

// containsFlowIndicator: the scalar must survive flow context ("[a, b]"),
// where , [ ] { } end a plain scalar wherever they appear — and go-yaml ends
// one at "?" too, so an unquoted URL with a query string would corrupt a
// resources: [...] list (found by sandbox.TestTextAuditorEmitsValidYAML).
func containsFlowIndicator(s string) bool { return strings.ContainsAny(s, ",[]{}?") }

// readsAsMappingOrComment: ": " (or a trailing ":") would turn the value into
// a mapping, and " #" starts a comment mid-scalar.
func readsAsMappingOrComment(s string) bool {
	return strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":")
}

// containsNonPrintable: control characters and other unprintables only
// survive inside a double-quoted scalar's escapes.
func containsNonPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return true
		}
	}
	return false
}

// readsAsNullBoolOrFloat: the words YAML resolves to null, a boolean or a
// special float, in any case ("Yes", "NULL", "-.Inf").
func readsAsNullBoolOrFloat(s string) bool {
	switch strings.ToLower(s) {
	case "~", "null", "true", "false", "yes", "no", "on", "off", "y", "n", ".inf", "-.inf", "+.inf", ".nan":
		return true
	}
	return false
}

// readsAsNumber: anything that could resolve numerically (600, 1e3, 0x1f,
// 1:30, -1, .5). Over-broad on purpose: a quoted number is still the same
// string, while a misread one is not.
func readsAsNumber(s string) bool {
	if s == "" {
		return false
	}
	if c := s[0]; '0' <= c && c <= '9' {
		return true
	}
	return len(s) > 1 && strings.ContainsRune("+-.", rune(s[0])) && '0' <= s[1] && s[1] <= '9'
}

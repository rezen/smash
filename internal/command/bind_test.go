package command

import (
	"reflect"
	"strings"
	"testing"
)

// TestSpecOfDerivesValueFlags: the parse Spec comes from the struct tags, so a
// string/[]string field's aliases are value flags, bools are not, extras are
// merged, and a subcommand field switches subcommand parsing on.
func TestSpecOfDerivesValueFlags(t *testing.T) {
	for _, fl := range []string{"-o", "--output", "-H", "--header", "--data-binary", "--connect-timeout"} {
		if !curlSpec.ValueFlags[fl] {
			t.Errorf("curlSpec should treat %s as a value flag", fl)
		}
	}
	for _, fl := range []string{"-s", "-L", "--fail"} {
		if curlSpec.ValueFlags[fl] {
			t.Errorf("curlSpec must not treat bool flag %s as a value flag", fl)
		}
	}
	if !curlSpec.ClusterShort || curlSpec.Subcommand {
		t.Errorf("curlSpec cluster/subcommand wrong: %+v", curlSpec)
	}
	if !opensslSpec.Subcommand || !opensslSpec.ValueFlags["-connect"] || !opensslSpec.ValueFlags["-CAfile"] {
		t.Errorf("opensslSpec wrong: %+v", opensslSpec)
	}
	// The derived spec is what the command actually parses with: -o consumes its value.
	if p := Parse([]string{"curl", "-o", "out", "https://x"}); len(p.Operands) != 1 || p.Operands[0] != "https://x" {
		t.Errorf("derived spec did not consume -o's value: %+v", p)
	}
}

func TestBindOperandsAndRest(t *testing.T) {
	p := Parse([]string{"openssl", "s_client", "-quiet", "-CAfile", "ca.pem", "-connect", "h:443", "-servername", "h", "extra"})
	o := opensslParamsFrom(p)
	want := OpensslParams{Subcommand: "s_client", Connect: "h:443", ServerName: "h",
		Rest: []string{"-CAfile", "ca.pem", "-quiet"}, Operands: []string{"extra"}}
	if !reflect.DeepEqual(o, want) {
		t.Errorf("bind = %+v, want %+v", o, want)
	}
	if got, wantS := o.String(), "openssl s_client -connect h:443 -servername h -CAfile ca.pem -quiet extra"; got != wantS {
		t.Errorf("String() = %q, want %q", got, wantS)
	}
	// Bound flags never leak into Rest, and unknown flags are preserved.
	if strings.Contains(strings.Join(o.Rest, " "), "-connect") {
		t.Errorf("Rest must exclude bound flags: %v", o.Rest)
	}
}

// TestWgetRoundTrip pins the wget quirks through the tag machinery: -O is the
// output, -o the logfile, and bools cluster on render.
func TestWgetRoundTrip(t *testing.T) {
	w := wgetParamsFrom(Parse([]string{"wget", "-q", "-c", "--output-document=f.tgz", "-o", "log", "--header", "A: 1", "https://x/y"}))
	if w.Output != "f.tgz" || w.Logfile != "log" || !w.Quiet || !w.Continue || len(w.Headers) != 1 {
		t.Fatalf("bind wrong: %+v", w)
	}
	if got, want := w.String(), "wget -qc -O f.tgz -o log --header 'A: 1' https://x/y"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if re := wgetParamsFrom(Parse(w.Args())); !reflect.DeepEqual(re, w) {
		t.Errorf("round-trip lost data: %+v vs %+v", re, w)
	}
}

// TestFieldsOfRejectsBadTags: a tag on an unsupported field type is a
// programming error caught the first time the type is used.
func TestFieldsOfRejectsBadTags(t *testing.T) {
	type bad struct {
		N int `flag:"-n"`
	}
	defer func() {
		if recover() == nil {
			t.Error("expected a panic for an int flag field")
		}
	}()
	fieldsOf(reflect.TypeOf(bad{}))
}

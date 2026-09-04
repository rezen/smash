package sandbox

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// runDetect executes src with only the detection CallHandler wired, a PATH that
// points nowhere real, and captured stdout — so a passing `command -v curl`
// proves the fake path came from interception, not the host.
func runDetect(t *testing.T, src string) (string, error) {
	t.Helper()
	prog, err := syntax.NewParser().Parse(strings.NewReader(src), "test")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	r, err := interp.New(
		interp.Env(expand.ListEnviron("PATH=/nonexistent-sandbox-path")),
		interp.StdIO(nil, &out, &out),
		interp.CallHandler(detectionCallHandler),
	)
	if err != nil {
		t.Fatal(err)
	}
	runErr := r.Run(context.Background(), prog)
	return out.String(), runErr
}

func TestDetectionInterceptsCurlWget(t *testing.T) {
	for _, tool := range []string{"curl", "wget"} {
		out, err := runDetect(t, "command -v "+tool)
		if err != nil {
			t.Fatalf("%s probe errored: %v", tool, err)
		}
		if want := "/opt/sandbox/bin/" + tool; !strings.Contains(out, want) {
			t.Errorf("command -v %s = %q, want %q (host-independent)", tool, strings.TrimSpace(out), want)
		}
	}
}

func TestDetectionPassesThroughOthers(t *testing.T) {
	// A tool that truly isn't on the (empty) PATH must still report missing —
	// the handler fakes ONLY downloaders, keeping other probes honest.
	out, _ := runDetect(t, "command -v definitely-not-real-xyz && echo FOUND || echo MISSING")
	if strings.Contains(out, "FOUND") || !strings.Contains(out, "MISSING") {
		t.Errorf("pass-through probe = %q, want MISSING", strings.TrimSpace(out))
	}
}

// TestCommandDefaultPathShim: `command -p NAME` (warp activates its symlink
// with `command -p mv -fh …`) runs as plain `command NAME`; `-pv` keeps -v.
func TestCommandDefaultPathShim(t *testing.T) {
	out, err := runDetect(t, "command -p echo hi; command -pv echo >/dev/null && echo probed")
	if err != nil {
		t.Fatal(err)
	}
	if out != "hi\nprobed\n" {
		t.Errorf("out = %q, want %q", out, "hi\nprobed\n")
	}
}

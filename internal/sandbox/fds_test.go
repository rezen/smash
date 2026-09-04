package sandbox

import (
	"strings"
	"testing"
)

// Both tests here run with the sandbox root as the working directory, so the
// relative paths they write land in the test's temp dir.

// TestExtraFileDescriptors pins the third_party/sh patch that gives the shell
// descriptors beyond 0/1/2. nvm's version lookup relies on the classic fd-swap
// idiom `{ v="$(f 3>&1 1>&4)"; } 4>&1` — f's fd 3 is captured while its stdout
// still reaches the terminal — and on `f 3>/dev/null` to discard it.
func TestExtraFileDescriptors(t *testing.T) {
	script := `
f() { echo captured >&3; echo shown; }
{ v="$(f 3>&1 1>&4)"; } 4>&1
echo "v=$v"
f 3>/dev/null
exec 3>&1
echo via-exec >&3
exec 3>&-
echo closed >&3 || echo write-failed
echo "hello" > in.txt
exec 5< in.txt
read -r line <&5
echo "line=$line"
echo x >&7
echo "status=$?"
`
	out, stderr, err := runConfined(t, script)
	if err != nil {
		t.Fatalf("err=%v out=%q stderr=%q", err, out, stderr)
	}
	want := "shown\nv=captured\nshown\nvia-exec\nline=hello\nstatus=1\n"
	if out != want {
		t.Errorf("stdout:\n%q\nwant:\n%q\nstderr: %s", out, want, stderr)
	}
	if !strings.Contains(stderr, "7: Bad file descriptor") {
		t.Errorf("writing to an unopened fd should fail like bash; stderr=%q", stderr)
	}
	if strings.Contains(stderr, "unsupported redirect fd") {
		t.Errorf("interpreter still rejects extra fds:\n%s", stderr)
	}
}

// TestNoclobber pins the second interpreter patch: `set -o noclobber` / `set -C`
// makes `>` refuse an existing file, `>|` overrides it, and the failure is a
// normal command error — so warp's lock idiom
// `(set -o noclobber; printf owner > lock) 2>/dev/null` acquires on the first
// try and fails on the second, under `set -e`.
func TestNoclobber(t *testing.T) {
	script := `
set -e
lock=.lock
if (set -o noclobber; printf first > "$lock") 2>/dev/null; then echo acquired; fi
if (set -o noclobber; printf second > "$lock") 2>/dev/null; then echo re-acquired; else echo held; fi
echo "content=$(cat "$lock")"
set -C
echo third > "$lock" 2>/dev/null || echo refused
echo fourth >| "$lock"
echo "content=$(cat "$lock")"
set +C
echo fifth > "$lock"
echo "content=$(cat "$lock")"
echo "flags=$-"
`
	out, stderr, err := runConfined(t, script)
	if err != nil {
		t.Fatalf("err=%v out=%q stderr=%q", err, out, stderr)
	}
	want := "acquired\nheld\ncontent=first\nrefused\ncontent=fourth\ncontent=fifth\nflags=e\n"
	if out != want {
		t.Errorf("stdout:\n%q\nwant:\n%q\nstderr: %s", out, want, stderr)
	}
	if !strings.Contains(stderr, ".lock: cannot overwrite existing file") || strings.Contains(stderr, "invalid option") {
		t.Errorf("stderr should carry bash's noclobber message and no option error:\n%s", stderr)
	}
}

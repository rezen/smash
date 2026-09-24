// Package manifest records and enforces the observable command and network
// surface of one exact script.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/network"
	"github.com/rezen/smash/internal/sandbox"
)

const Version = 1

// Manifest is a reviewed profile for one exact script body. The list fields
// are sorted and de-duplicated when a profile is written.
type Manifest struct {
	Version  int      `yaml:"version"`
	OS       string   `yaml:"os,omitempty"`
	Script   Script   `yaml:"script"`
	Commands []string `yaml:"commands"`
	// URLs are owner/repo URL prefixes for project-shaped GitHub-family
	// downloads, applied as sandbox.Policy.AllowedPrefixes (scheme-pinned,
	// whole-segment matching) — so a profiled GitHub fetch grants one
	// project, not the whole forge. The Profiler records them via
	// sandbox.GitHubProjectPrefix; hosts whose paths carry no project
	// identity (non-GitHub vendors, GitHub's opaque uuid/hash asset hosts)
	// stay in Hosts. Any valid URL prefix is accepted when hand-editing.
	URLs  []string `yaml:"urls,omitempty"`
	Hosts []string `yaml:"hosts"`
	// MIMETypes, when present, is the response-body MIME allow-list applied
	// on top of the hosts (see sandbox.Policy.AllowedMIMETypes). The Profiler
	// records the declared media types it observed — downloads run through
	// the shared in-process downloader even under -profile — but omits the
	// field entirely when any observed body lacked a parseable declared
	// Content-Type: enforcement denies a missing Content-Type whenever a
	// list is set, so writing one would break replaying the very script that
	// was profiled. Hand-editing during review remains the norm. Absent means
	// no MIME restriction; an explicit empty list denies every response body.
	MIMETypes []string `yaml:"mime-types,omitempty"`
}

type Script struct {
	Name   string `yaml:"name,omitempty"`
	SHA256 string `yaml:"sha256"`
}

// New creates the immutable portion of a profile.
func New(name, source string) Manifest {
	sum := sha256.Sum256([]byte(source))
	return Manifest{
		Version: Version,
		OS:      runtime.GOOS,
		Script:  Script{Name: name, SHA256: hex.EncodeToString(sum[:])},
	}
}

// Verify checks that m is supported and belongs to source.
func (m Manifest) Verify(source string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if m.OS != "" && m.OS != runtime.GOOS {
		return fmt.Errorf("manifest OS mismatch: manifest has %s, current OS is %s", m.OS, runtime.GOOS)
	}
	sum := sha256.Sum256([]byte(source))
	got := hex.EncodeToString(sum[:])
	if got != m.Script.SHA256 {
		return fmt.Errorf("script SHA-256 mismatch: manifest has %s, script is %s", m.Script.SHA256, got)
	}
	return nil
}

func (m Manifest) Validate() error {
	if m.Version != Version {
		return fmt.Errorf("unsupported manifest version %d (want %d)", m.Version, Version)
	}
	if len(m.Script.SHA256) != sha256.Size*2 {
		return fmt.Errorf("manifest script.sha256 must be a 64-character SHA-256")
	}
	if _, err := hex.DecodeString(m.Script.SHA256); err != nil {
		return fmt.Errorf("manifest script.sha256: %w", err)
	}
	for _, name := range m.Commands {
		if name == "" || filepath.Base(name) != name {
			return fmt.Errorf("invalid manifest command %q: use a command name, not a path", name)
		}
	}
	for _, entry := range m.URLs {
		if err := sandbox.ValidateURLPrefix(entry); err != nil {
			return fmt.Errorf("manifest urls: %w", err)
		}
	}
	for _, host := range m.Hosts {
		if !network.ValidHost(host) {
			return fmt.Errorf("invalid manifest host %q", host)
		}
	}
	for _, entry := range m.MIMETypes {
		if err := sandbox.ValidateMIMERule(entry); err != nil {
			return fmt.Errorf("manifest mime-types: %w", err)
		}
	}
	return nil
}

// Load decodes a manifest and rejects unknown fields.
func Load(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &m, nil
}

// Write stores m as stable, review-friendly YAML.
func (m Manifest) Write(path string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".smash-manifest-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(tmp)
		}
	}()
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		f.Close()
		return err
	}
	if err := enc.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	keep = true
	return nil
}

// Apply makes the manifest the command and network authority for cfg: URLs
// become the run's prefix grants (scheme-pinned, whole-segment), Hosts its
// exact host grants, and Hosts alone feed explicitly allowed Git. Other
// policy controls (mocks, limits, disabled commands, environment) stay
// intact, as does a policy's MIME allow-list unless the manifest states its
// own.
func (m Manifest) Apply(cfg *sandbox.Config) {
	cfg.Strict = true
	cfg.Allowed = command.NewSet(m.Commands...)
	cfg.Network.AllowedPrefixes = append([]string(nil), m.URLs...)
	cfg.Network.AllowedHosts = append([]string(nil), m.Hosts...)
	cfg.Network.GitHosts = append([]string(nil), m.Hosts...)
	if m.MIMETypes != nil {
		cfg.Network.AllowedMIMETypes = append([]string(nil), m.MIMETypes...)
	}
}

// Profiler is a concurrency-safe Auditor that gathers a manifest while
// forwarding records to Next (normally TextAuditor).
type Profiler struct {
	Next sandbox.Auditor

	mu         sync.Mutex
	manifest   Manifest
	commands   map[string]bool
	urls       map[string]bool
	hosts      map[string]bool
	mimeTypes  map[string]bool
	sawUntyped bool // a download body arrived without a parseable declared type
}

func NewProfiler(name, source string, next sandbox.Auditor) *Profiler {
	return &Profiler{
		Next: next, manifest: New(name, source),
		commands: map[string]bool{}, urls: map[string]bool{},
		hosts: map[string]bool{}, mimeTypes: map[string]bool{},
	}
}

func (p *Profiler) Audit(rec sandbox.AuditRecord) {
	p.mu.Lock()
	if rec.Name != "" {
		p.commands[filepath.Base(rec.Name)] = true
	}
	for _, resource := range rec.Resources {
		if resource.Kind == "url" {
			p.recordURL(resource.Value)
		} else if host := resourceHost(resource); host != "" {
			p.hosts[host] = true
		}
	}
	// The in-process downloader observes what parsed argv cannot: the URL of
	// every redirect hop, and the response's declared media type.
	for _, hop := range rec.Via {
		p.recordURL(hop)
	}
	if rec.ContentType != "" {
		p.mimeTypes[rec.ContentType] = true
	}
	if rec.Sniffed != "" && rec.ContentType == "" {
		p.sawUntyped = true
	}
	p.mu.Unlock()
	if p.Next != nil {
		p.Next.Audit(rec)
	}
}

func (p *Profiler) AuditOpen(rec sandbox.OpenRecord) {
	if next, ok := p.Next.(sandbox.OpenAuditor); ok {
		next.AuditOpen(rec)
	}
}

func (p *Profiler) Manifest() Manifest {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.manifest
	for name := range p.commands {
		m.Commands = append(m.Commands, name)
	}
	for prefix := range p.urls {
		m.URLs = append(m.URLs, prefix)
	}
	for host := range p.hosts {
		m.Hosts = append(m.Hosts, host)
	}
	if !p.sawUntyped {
		for mt := range p.mimeTypes {
			m.MIMETypes = append(m.MIMETypes, mt)
		}
	}
	sort.Strings(m.Commands)
	sort.Strings(m.URLs)
	sort.Strings(m.Hosts)
	sort.Strings(m.MIMETypes)
	return m
}

// recordURL classifies one observed URL — an argv fetch target or a redirect
// hop: a project-shaped GitHub-family URL becomes an owner/repo prefix in
// urls; everything else falls back to its host. Both spellings come from the
// SAME parsers (sandbox.GitHubProjectPrefix, network.HostFromEndpoint) that
// enforcement matches with, so recording and matching cannot drift apart.
func (p *Profiler) recordURL(raw string) {
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			if prefix, ok := sandbox.GitHubProjectPrefix(u); ok {
				p.urls[prefix] = true
				return
			}
		}
	}
	if host := network.HostFromEndpoint(raw); host != "" {
		p.hosts[host] = true
	}
}

// resourceHost extracts the host a network-ish resource touched, with the
// SAME parser (network.HostFromEndpoint) Policy.AllowsTarget will use when
// this manifest is later enforced — recording and matching cannot drift
// apart. Resources of kind "url" go through recordURL instead, where a
// project-shaped GitHub URL keeps its owner/repo path.
func resourceHost(r command.Resource) string {
	switch r.Kind {
	case "repo", "remote", "host", "socket", "keyserver":
	default:
		return ""
	}
	return network.HostFromEndpoint(r.Value)
}

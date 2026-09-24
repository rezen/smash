package sandbox

// The audit log: one AuditRecord per executed command — what it was (the
// normalized command line and its typed params), what it touched (resources),
// how it ended (exit status, duration) and, when data capture is on, what
// flowed through its stdin and stdout. Piped stages show their streams, so a
// `curl … | base64 -d | sh` chain is legible as three linked records with the
// bytes that passed between them. Header, cookie and password values are never
// resources, and the command line and params are redacted (command.Redact)
// before they reach a record. Captured stream data is raw — it is what the
// command actually read and wrote.
//
// Opt in with Config.Auditor (TextAuditor for a log, or your own for JSON/…);
// Config.AuditData > 0 captures up to that many bytes per stream per command.
//
// Commands aren't the only thing that touches files: the shell itself opens
// them for redirections (`> f`, `>> f`, `< f`, `exec 3< f`) and `source`. Those
// never pass through the exec chain, so an Auditor that also implements
// OpenAuditor receives one OpenRecord per shell open — otherwise
// `echo "$TOKEN" > ~/.netrc` would leave no trace.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/tool"
)

// AuditRecord is everything the sandbox knows about one executed command.
type AuditRecord struct {
	Name        string               // command name (after wrapper unwrapping)
	Command     string               // normalized command line, e.g. "base64 -d" (secrets redacted)
	Params      command.Params       // typed params (Base64Params, CurlParams, …) or the generic ParsedCommand, redacted
	Resources   []command.Resource   // what it touched: "read stdin", "fetch url …"
	Files       []command.FileChange // filesystem changes, for monitoring: "delete /x (recursive)"
	Exit        error                // nil on success; interp.ExitStatus(n) otherwise
	Reason      string               // the sandbox's own diagnostic when IT failed the command (blocked, off-list URL…); "" if the program ran
	ContentType string               // declared Content-Type of an in-process download's response, parameters stripped; "" when absent or the response had no body
	Sniffed     string               // what the body's first bytes actually are (http.DetectContentType plus magic-byte refinement: tar, xz, executables, shebangs…); set whenever a download's response carried a body
	Via         []string             // full URL of every hop an in-process download passed through, initial request first; rendered only when a redirect occurred
	Wrappers    []string             // the wrapper commands peeled off to reach this one, outermost first: sudo, env, timeout, xargs, find (see command.Unwrap)
	Unlisted    bool                 // the program ran although it is on neither the allow-list nor inside the root (see DefaultAllowList)
	InRoot      bool                 // the program ran through the in-sandbox escape hatch: it resolved inside Config.Root
	Duration    time.Duration
	Stdin       Capture // data read from stdin (only when AuditData > 0)
	Stdout      Capture // data written to stdout
}

// Capture is a bounded copy of a stream: the first Cap bytes plus the total.
type Capture struct {
	Data  []byte
	Total int64 // bytes that actually flowed, which may exceed len(Data)
}

func (c Capture) String() string {
	if c.Total == 0 {
		return ""
	}
	s := strconv.Quote(string(c.Data))
	if int64(len(c.Data)) < c.Total {
		s += fmt.Sprintf(" …(+%d B)", c.Total-int64(len(c.Data)))
	}
	return s
}

// Auditor receives one record per executed command.
//
// Audit (and AuditOpen, for an OpenAuditor) MAY BE CALLED CONCURRENTLY: the
// interpreter runs the stages of a pipeline and every backgrounded command on
// their own goroutines, and each one records itself. An implementation must
// serialise its own writes — TextAuditor holds a mutex for exactly this.
type Auditor interface {
	Audit(rec AuditRecord)
}

// AuditorFunc adapts a function to Auditor.
type AuditorFunc func(rec AuditRecord)

func (f AuditorFunc) Audit(rec AuditRecord) { f(rec) }

// MultiAuditor fans every record out to all of auditors, the way
// io.MultiWriter duplicates writes; shell-open records reach the ones that
// implement OpenAuditor. Useful when one stream feeds a live view and
// another a file kept beside a generated artifact. nil entries are skipped.
func MultiAuditor(auditors ...Auditor) OpenAuditor { return multiAuditor(auditors) }

type multiAuditor []Auditor

func (m multiAuditor) Audit(rec AuditRecord) {
	for _, a := range m {
		if a != nil {
			a.Audit(rec)
		}
	}
}

func (m multiAuditor) AuditOpen(rec OpenRecord) {
	for _, a := range m {
		if oa, ok := a.(OpenAuditor); ok {
			oa.AuditOpen(rec)
		}
	}
}

// OpenRecord is one file the shell opened for itself — a redirection or a
// `source` — as opposed to a file a command opened on its own behalf (those
// are AuditRecord.Files, derived from the command's params). Path is as the
// script wrote it, relative to the working directory when not absolute, like
// the paths in an AuditRecord.
type OpenRecord struct {
	Path string
	Op   OpenOp // what the open does to the file
	Flag int    // the raw os.O_* flags the shell asked for
	Err  error  // nil when the open succeeded
}

// OpenOp is what a shell open does to its file.
type OpenOp string

const (
	OpenRead   OpenOp = "read"   // `< f`, `source f`, `exec 3< f`
	OpenWrite  OpenOp = "write"  // `> f`: create or truncate
	OpenAppend OpenOp = "append" // `>> f`: create or append
)

// openOp classifies the flags the interpreter passes: `>` is
// O_WRONLY|O_CREATE|O_TRUNC (O_EXCL instead of O_TRUNC under noclobber), `>>`
// is O_WRONLY|O_CREATE|O_APPEND, all else reads.
func openOp(flag int) OpenOp {
	switch {
	case flag&os.O_APPEND != 0:
		return OpenAppend
	case flag&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC|os.O_CREATE) != 0:
		return OpenWrite
	}
	return OpenRead
}

// Resource renders the open as an audit resource: "write path f".
func (r OpenRecord) Resource() command.Resource {
	return command.Resource{Kind: "path", Action: string(r.Op), Value: r.Path}
}

// Change is the filesystem change a successful write or append makes, so a
// monitor can treat `> f` and `tee f` alike. Reads and failed opens have none.
func (r OpenRecord) Change() (command.FileChange, bool) {
	if r.Err != nil {
		return command.FileChange{}, false
	}
	switch r.Op {
	case OpenWrite:
		return command.FileChange{Op: command.FileWrite, Path: r.Path}, true
	case OpenAppend:
		return command.FileChange{Op: command.FileAppend, Path: r.Path}, true
	}
	return command.FileChange{}, false
}

// OpenAuditor is an Auditor that also receives the shell's own file opens.
// TextAuditor implements it; an AuditorFunc does not. Opens of /dev/null are
// not reported.
type OpenAuditor interface {
	Auditor
	AuditOpen(rec OpenRecord)
}

// TextAuditor writes records to w as a YAML stream — one sequence item per
// record, so a log is a valid YAML document a tool such as yq can query:
//
//	# one item per executed command
//	- name: curl
//	  resources: [fetch url https://x/uv.tgz, write path ~/uv.tgz]
//	  command: curl -fsSL https://x/uv.tgz -o ~/uv.tgz
//	  params: !CurlParams {Silent: true, ShowError: true, FailFast: true, Follow: true, URL: https://x/uv.tgz, Output: ~/uv.tgz}
//	  files: [delete ~/.cache (recursive)]   # only changes resources doesn't already say
//	  exit: 0
//	  content-type: application/gzip         # declared by the response; sniffed/via appear when they add information
//	  duration: 120ms
//	  stdin: {bytes: 8, data: "aGVsbG8="}
//	  stdout: {bytes: 5, data: "hello"}
//
// and, for the shell's own opens (redirections, `source`):
//
//	# one item per redirection or source
//	- name: shell
//	  resources: [append path ~/.bashrc]
//	- name: shell
//	  resources: [read path missing.txt]
//	  error: "open missing.txt: no such file or directory"
//
// Keys mirror AuditRecord: exit is the status when the program ran, error the
// message when it could not, and reason is the sandbox's diagnostic when it
// failed the command. Params carry the type as a local tag and list only the
// fields that are set. Captured data is always double-quoted; everything else
// is plain unless YAML requires quoting. With ShortPaths, absolute paths
// inside the sandbox are written as ~/…, $TMPDIR/… and $ROOT/… so a line fits
// on a screen; the records themselves are untouched.
func TextAuditor(w io.Writer, opts ...TextOption) Auditor {
	t := &textAuditor{w: w}
	for _, o := range opts {
		o(t)
	}
	sort.SliceStable(t.short, func(i, j int) bool { return len(t.short[i].prefix) > len(t.short[j].prefix) })
	return t
}

// TextOption adjusts how TextAuditor renders records.
type TextOption func(*textAuditor)

// ShortPaths makes TextAuditor write paths under the sandbox as ~/… (HOME),
// $TMPDIR/… and $ROOT/… (cfg.Root) instead of the full absolute path. It reads
// HOME and TMPDIR from cfg.Env, so build cfg first.
func ShortPaths(cfg Config) TextOption {
	return func(t *textAuditor) {
		for _, a := range []pathAbbrev{
			{cfg.Env.Get("HOME").String(), "~"},
			{cfg.Env.Get("TMPDIR").String(), "$TMPDIR"},
			{cfg.Root, "$ROOT"},
		} {
			if a.prefix != "" && a.prefix != "/" {
				t.short = append(t.short, a)
			}
		}
	}
}

type pathAbbrev struct{ prefix, short string }

type textAuditor struct {
	// mu serialises writes to w. Records arrive from several goroutines at
	// once — one per pipeline stage, one per backgrounded command — and a
	// half-written record interleaved with another is not YAML any more.
	mu    sync.Mutex
	w     io.Writer
	short []pathAbbrev // longest prefix first, fixed after construction
}

// write emits one finished record.
func (t *textAuditor) write(s string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	io.WriteString(t.w, s)
}

func (t *textAuditor) AuditOpen(r OpenRecord) {
	var rec yamlRecord
	rec.add("name", "shell")
	rec.add("resources", t.list([]string{r.Resource().String()}))
	if r.Err != nil {
		rec.add("error", t.scalar(r.Err.Error()))
	}
	t.write(rec.String())
}

func (t *textAuditor) Audit(r AuditRecord) {
	var rec yamlRecord
	rec.add("name", t.scalar(r.Name))
	said := map[string]bool{} // resources already listed, to keep files from repeating them
	if len(r.Resources) > 0 {
		parts := make([]string, len(r.Resources))
		for i, res := range r.Resources {
			parts[i] = res.String()
			said[parts[i]] = true
		}
		rec.add("resources", t.list(parts))
	}
	rec.add("command", t.scalar(r.Command))
	if _, generic := r.Params.(command.ParsedCommand); !generic && r.Params != nil {
		if ps := t.params(r.Params); ps != "" {
			rec.add("params", ps)
		}
	}
	var files []string
	for _, c := range r.Files {
		if said[c.Resource().String()] && !c.Recursive {
			continue // resources already says "delete path x"
		}
		files = append(files, c.String())
	}
	if len(files) > 0 {
		rec.add("files", t.list(files))
	}
	if code, ok := exitCode(r.Exit); ok {
		rec.add("exit", strconv.Itoa(code))
	} else {
		rec.add("error", t.scalar(r.Exit.Error()))
	}
	if r.Reason != "" {
		rec.add("reason", t.scalar(r.Reason))
	}
	if r.ContentType != "" {
		rec.add("content-type", t.scalar(r.ContentType))
	}
	if r.Sniffed != "" && r.Sniffed != r.ContentType {
		rec.add("sniffed", t.scalar(r.Sniffed))
	}
	if len(r.Via) > 1 { // more than one hop = a redirect actually happened
		rec.add("via", t.list(r.Via))
	}
	if len(r.Wrappers) > 0 {
		rec.add("wrappers", t.list(r.Wrappers))
	}
	if r.Unlisted {
		rec.add("unlisted", "true")
	}
	if r.InRoot {
		rec.add("in-root", "true")
	}
	rec.add("duration", durationString(r.Duration))
	if r.Stdin.Total > 0 {
		rec.add("stdin", captureYAML(r.Stdin))
	}
	if r.Stdout.Total > 0 {
		rec.add("stdout", captureYAML(r.Stdout))
	}
	t.write(rec.String())
}

// yamlRecord accumulates one item of the sequence: "- key: value" and then
// "  key: value" lines. Values arrive already rendered as YAML.
type yamlRecord struct{ b strings.Builder }

func (r *yamlRecord) add(key, value string) {
	if r.b.Len() == 0 {
		r.b.WriteString("- ")
	} else {
		r.b.WriteString("  ")
	}
	r.b.WriteString(key)
	r.b.WriteString(": ")
	r.b.WriteString(value)
	r.b.WriteByte('\n')
}

func (r *yamlRecord) String() string { return r.b.String() }

// scalar renders one text value: paths abbreviated, then quoted if YAML needs it.
func (t *textAuditor) scalar(s string) string { return yamlScalar(t.shorten(s)) }

// list renders values as a flow sequence: [a, b].
func (t *textAuditor) list(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = t.scalar(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// params renders typed params as a tagged flow mapping of the fields that are
// set — `base64 -d` is `!Base64Params {Decode: true}` — or "" when none are.
func (t *textAuditor) params(p command.Params) string {
	v := reflect.ValueOf(p)
	for v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return t.scalar(fmt.Sprint(p))
	}
	typ := v.Type()
	var fields []string
	for i := range typ.NumField() {
		f := typ.Field(i)
		fv := v.Field(i)
		if !f.IsExported() || fv.IsZero() || fv.Kind() == reflect.Slice && fv.Len() == 0 {
			continue // Redact leaves empty non-nil slices behind; they're unset too
		}
		var val string
		switch x := fv.Interface().(type) {
		case string:
			val = t.scalar(x)
		case []string:
			val = t.list(x)
		default:
			val = fmt.Sprint(x) // bools and numbers are YAML as printed
		}
		fields = append(fields, f.Name+": "+val)
	}
	if len(fields) == 0 {
		return ""
	}
	return "!" + typ.Name() + " {" + strings.Join(fields, ", ") + "}"
}

// captureYAML renders a stream capture: the bytes that flowed and the
// (possibly capped) data, always quoted since it is raw.
func captureYAML(c Capture) string {
	return fmt.Sprintf("{bytes: %d, data: %s}", c.Total, strconv.Quote(string(c.Data)))
}

// shorten applies the ShortPaths abbreviations to one value.
func (t *textAuditor) shorten(s string) string {
	for _, a := range t.short {
		s = replacePathPrefix(s, a.prefix, a.short)
	}
	return s
}

// replacePathPrefix rewrites every occurrence of prefix that stands as a whole
// path or path prefix — not the /x/tmp inside /x/tmpfiles — as short.
func replacePathPrefix(s, prefix, short string) string {
	if !strings.Contains(s, prefix) {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, prefix)
		if i < 0 {
			break
		}
		end := i + len(prefix)
		whole := (i == 0 || !isPathByte(s[i-1])) && (end == len(s) || s[end] == '/' || !isPathByte(s[end]))
		b.WriteString(s[:i])
		if whole {
			b.WriteString(short)
		} else {
			b.WriteString(prefix)
		}
		s = s[end:]
	}
	b.WriteString(s)
	return b.String()
}

func isPathByte(c byte) bool {
	return c == '/' || c == '.' || c == '_' || c == '-' || c == '~' ||
		'0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// yamlScalar renders s as a YAML scalar: plain when a parser would read it
// back unchanged as a string, otherwise double-quoted. Quoting is decided for
// flow context (the stricter one), so the same rule serves block values,
// sequence items and mapping values alike. Go's quoted form is valid YAML:
// both use \n, \t, \", \\, \xNN, \uNNNN and \UNNNNNNNN.
func yamlScalar(s string) string {
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
// resources: [...] list (found by TestTextAuditorEmitsValidYAML).
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

func durationString(d time.Duration) string {
	if d < time.Millisecond {
		return "<1ms"
	}
	return d.Round(time.Millisecond).String()
}

// exitCode is the status the command ended with: 0 for success, n for
// interp.ExitStatus(n); false when the error is not an exit status at all.
func exitCode(err error) (int, bool) {
	if err == nil {
		return 0, true
	}
	if code, ok := interp.IsExitStatus(err); ok {
		return int(code), true
	}
	return 0, false
}

// auditMiddleware records every exec. With dataCap > 0 it tees the command's
// stdin and stdout through bounded buffers by handing the next handler a
// context whose HandlerContext carries the tee'd streams.
func auditMiddleware(a Auditor, dataCap int) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
		return func(ctx context.Context, args []string) error {
			if len(args) == 0 {
				return next(ctx, args)
			}
			p := command.Parse(args)
			var in, out capBuf
			if dataCap > 0 {
				hc := interp.HandlerCtx(ctx)
				in.limit, out.limit = dataCap, dataCap
				if hc.Stdin != nil {
					hc.Stdin = io.TeeReader(hc.Stdin, &in)
				}
				hc.Stdout = io.MultiWriter(hc.Stdout, &out)
				ctx = interp.WithHandlerContext(ctx, hc)
			}
			ctx, note := withGateNote(ctx)              // filled in by the command gate
			ctx, respNote := tool.WithResponseNote(ctx) // filled in by the in-process downloader
			start := time.Now()
			err := next(ctx, args)
			params := command.Redact(p.TypedParams()) // never log credentials
			var reason string
			if f, ok := errors.AsType[*Failure](err); ok {
				reason = f.Msg
			}
			a.Audit(AuditRecord{
				Name:        p.Name,
				Command:     params.String(),
				Params:      params,
				Resources:   p.Resources(),
				Files:       p.FileChanges(),
				Exit:        err,
				Reason:      reason,
				ContentType: respNote.ContentType,
				Sniffed:     respNote.Sniffed,
				Via:         respNote.Via,
				Wrappers:    wrappersFrom(ctx),
				Unlisted:    note.Unlisted,
				InRoot:      note.InRoot,
				Duration:    time.Since(start),
				Stdin:       in.capture(),
				Stdout:      out.capture(),
			})
			return err
		}
	}
}

// auditOpenMiddleware reports every shell open — after the rest of the open
// chain has run, so the record carries the real outcome (a denied /dev/tcp
// open shows up with its error). /dev/null is skipped: `2>/dev/null` is in
// every installer and changes nothing.
func auditOpenMiddleware(a OpenAuditor) OpenMiddleware {
	return func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc {
		return func(ctx context.Context, name string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			f, err := next(ctx, name, flag, perm)
			if name != os.DevNull {
				a.AuditOpen(OpenRecord{Path: name, Op: openOp(flag), Flag: flag, Err: err})
			}
			return f, err
		}
	}
}

// capBuf keeps the first limit bytes written and counts the rest.
type capBuf struct {
	buf   bytes.Buffer
	total int64
	limit int
}

func (c *capBuf) Write(p []byte) (int, error) {
	n := len(p)
	c.total += int64(n)
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		c.buf.Write(p)
	}
	return n, nil // never a short write: the cap drops data, it doesn't fail the pipe
}

func (c *capBuf) capture() Capture { return Capture{Data: c.buf.Bytes(), Total: c.total} }

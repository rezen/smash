package tool

// sha256sum is implemented in-process because GNU coreutils is not available
// on every host (notably macOS). Installers can therefore use the usual Linux
// checksum command without weakening the command gate or requiring a shim on
// PATH.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

func SHA256Sum(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 || filepath.Base(args[0]) != "sha256sum" {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		opts, err := parseSHA256Sum(args[1:])
		if err != nil {
			return Failf(hc.Stderr, 1, "sha256sum: %v", err)
		}
		if opts.check {
			return checkSHA256Sums(ctx, hc, opts)
		}
		return writeSHA256Sums(ctx, hc, opts)
	}
}

type sha256sumOptions struct {
	check         bool
	binary        bool
	tag           bool
	zero          bool
	quiet         bool
	status        bool
	ignoreMissing bool
	strict        bool
	warn          bool
	files         []string
}

func parseSHA256Sum(args []string) (sha256sumOptions, error) {
	var o sha256sumOptions
	options := true
	for _, arg := range args {
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			switch arg {
			case "-b", "--binary":
				o.binary = true
			case "-t", "--text":
				o.binary = false
			case "-c", "--check":
				o.check = true
			case "--tag":
				o.tag = true
			case "-z", "--zero":
				o.zero = true
			case "--quiet":
				o.quiet = true
			case "--status":
				o.status = true
			case "--ignore-missing":
				o.ignoreMissing = true
			case "--strict":
				o.strict = true
			case "-w", "--warn":
				o.warn = true
			default:
				return o, fmt.Errorf("unrecognized option %q", arg)
			}
			continue
		}
		o.files = append(o.files, arg)
	}
	if len(o.files) == 0 {
		o.files = []string{"-"}
	}
	if !o.check && (o.quiet || o.status || o.ignoreMissing || o.strict || o.warn) {
		return o, fmt.Errorf("the --quiet, --status, --ignore-missing, --strict and --warn options are meaningful only when verifying checksums")
	}
	if o.check && (o.tag || o.zero) {
		return o, fmt.Errorf("the --tag and --zero options are not supported when verifying checksums")
	}
	return o, nil
}

func writeSHA256Sums(ctx context.Context, hc interp.HandlerContext, o sha256sumOptions) error {
	failed := false
	for _, name := range o.files {
		digest, err := sha256File(ctx, hc, name)
		if err != nil {
			fmt.Fprintf(hc.Stderr, "sha256sum: %s: %v\n", name, fileError(err))
			failed = true
			continue
		}
		if o.tag {
			fmt.Fprintf(hc.Stdout, "SHA256 (%s) = %s\n", name, digest)
			continue
		}
		marker := "  "
		if o.binary {
			marker = " *"
		}
		line := digest + marker + name
		if !o.zero && strings.ContainsAny(name, "\\\n") {
			line = "\\" + digest + marker + escapeChecksumName(name)
		}
		terminator := byte('\n')
		if o.zero {
			terminator = 0
		}
		fmt.Fprint(hc.Stdout, line)
		_, _ = hc.Stdout.Write([]byte{terminator})
	}
	if failed {
		return interp.ExitStatus(1)
	}
	return nil
}

func sha256File(ctx context.Context, hc interp.HandlerContext, name string) (string, error) {
	var r io.Reader = hc.Stdin
	var closeFile io.Closer
	if name != "-" {
		path := name
		if !filepath.IsAbs(path) {
			path = filepath.Join(hc.Dir, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		r, closeFile = f, f
	}
	if closeFile != nil {
		defer closeFile.Close()
	}
	h := sha256.New()
	if _, err := io.Copy(h, &contextReader{ctx: ctx, r: r}); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func checkSHA256Sums(ctx context.Context, hc interp.HandlerContext, o sha256sumOptions) error {
	valid, malformed, failed := 0, 0, false
	for _, listName := range o.files {
		var r io.Reader = hc.Stdin
		var f *os.File
		if listName != "-" {
			path := listName
			if !filepath.IsAbs(path) {
				path = filepath.Join(hc.Dir, path)
			}
			var err error
			f, err = os.Open(path)
			if err != nil {
				if !o.status {
					fmt.Fprintf(hc.Stderr, "sha256sum: %s: %v\n", listName, fileError(err))
				}
				failed = true
				continue
			}
			r = f
		}
		scanner := bufio.NewScanner(&contextReader{ctx: ctx, r: r})
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			expected, name, ok := parseChecksumLine(strings.TrimSuffix(scanner.Text(), "\r"))
			if !ok {
				malformed++
				if o.warn && !o.status {
					fmt.Fprintf(hc.Stderr, "sha256sum: %s: %d: improperly formatted SHA256 checksum line\n", listName, lineNo)
				}
				continue
			}
			valid++
			actual, err := sha256File(ctx, hc, name)
			if err != nil {
				if o.ignoreMissing && os.IsNotExist(err) {
					continue
				}
				if !o.status {
					fmt.Fprintf(hc.Stdout, "%s: FAILED open or read\n", name)
					fmt.Fprintf(hc.Stderr, "sha256sum: %s: %v\n", name, fileError(err))
				}
				failed = true
				continue
			}
			if !strings.EqualFold(actual, expected) {
				if !o.status {
					fmt.Fprintf(hc.Stdout, "%s: FAILED\n", name)
				}
				failed = true
			} else if !o.quiet && !o.status {
				fmt.Fprintf(hc.Stdout, "%s: OK\n", name)
			}
		}
		if err := scanner.Err(); err != nil {
			if !o.status {
				fmt.Fprintf(hc.Stderr, "sha256sum: %s: %v\n", listName, err)
			}
			failed = true
		}
		if f != nil {
			_ = f.Close()
		}
	}
	if valid == 0 {
		if !o.status {
			fmt.Fprintln(hc.Stderr, "sha256sum: no properly formatted checksum lines found")
		}
		failed = true
	}
	if malformed > 0 && o.strict {
		failed = true
	}
	if failed {
		return interp.ExitStatus(1)
	}
	return nil
}

func parseChecksumLine(line string) (digest, name string, ok bool) {
	escaped := strings.HasPrefix(line, "\\")
	if escaped {
		line = line[1:]
	}
	if len(line) < 66 || line[64] != ' ' || (line[65] != ' ' && line[65] != '*') {
		return "", "", false
	}
	digest, name = line[:64], line[66:]
	if _, err := hex.DecodeString(digest); err != nil {
		return "", "", false
	}
	if escaped {
		var good bool
		name, good = unescapeChecksumName(name)
		if !good {
			return "", "", false
		}
	}
	return digest, name, name != ""
}

func escapeChecksumName(name string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n").Replace(name)
}

func unescapeChecksumName(name string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		if name[i] != '\\' {
			b.WriteByte(name[i])
			continue
		}
		i++
		if i == len(name) {
			return "", false
		}
		switch name[i] {
		case '\\':
			b.WriteByte('\\')
		case 'n':
			b.WriteByte('\n')
		default:
			return "", false
		}
	}
	return b.String(), true
}

func fileError(err error) error {
	if pathErr, ok := err.(*os.PathError); ok {
		return pathErr.Err
	}
	return err
}

package tool

// mktemp is implemented in-process so its default directory follows the
// runner's TMPDIR on every host. In particular, BSD mktemp can use a
// platform-selected directory instead of the TMPDIR supplied to the script.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/interp"
)

// Mktemp intercepts mktemp before the command gate and implements
// the common GNU/BSD forms used by installers. Templates with an explicit
// directory keep that directory; otherwise -p/-t or TMPDIR chooses it.
func Mktemp(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 || filepath.Base(args[0]) != "mktemp" {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		opts, err := parseMktemp(args[1:])
		if err != nil {
			if opts.quiet {
				return interp.ExitStatus(1)
			}
			return Failf(hc.Stderr, 1, "mktemp: %v", err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		tmpDir := hc.Env.Get("TMPDIR").String()
		if tmpDir == "" {
			tmpDir = os.TempDir()
		}
		if !filepath.IsAbs(tmpDir) {
			tmpDir = filepath.Join(hc.Dir, tmpDir)
		}

		template := opts.template
		if template == "" {
			template = "tmp.XXXXXXXXXX"
		}
		dir, base := filepath.Split(template)
		if opts.useTempDir {
			dir = opts.tempDir
			if dir == "" {
				dir = tmpDir
			} else if !filepath.IsAbs(dir) {
				dir = filepath.Join(hc.Dir, dir)
			}
			dir = filepath.Clean(dir)
			base = filepath.Base(template)
		} else if dir != "" {
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(hc.Dir, dir)
			}
			dir = filepath.Clean(dir)
		} else {
			dir = tmpDir
			base = filepath.Base(template)
		}
		if opts.suffix != "" {
			if strings.ContainsAny(opts.suffix, `/\\`) {
				return Failf(hc.Stderr, 1, "mktemp: suffix must not contain a path separator")
			}
			base += opts.suffix
		}
		pattern, err := mktempPattern(base)
		if err != nil {
			return Failf(hc.Stderr, 1, "mktemp: %v", err)
		}

		var name string
		if opts.directory {
			name, err = os.MkdirTemp(dir, pattern)
		} else {
			var f *os.File
			f, err = os.CreateTemp(dir, pattern)
			if err == nil {
				name = f.Name()
				err = f.Close()
			}
		}
		if err != nil {
			if opts.quiet {
				return interp.ExitStatus(1)
			}
			return Failf(hc.Stderr, 1, "mktemp: %v", err)
		}
		if opts.dryRun {
			err = os.Remove(name)
			if err != nil {
				return Failf(hc.Stderr, 1, "mktemp: %v", err)
			}
		}
		fmt.Fprintln(hc.Stdout, name)
		return nil
	}
}

type mktempOptions struct {
	directory  bool
	dryRun     bool
	quiet      bool
	useTempDir bool
	tempDir    string
	template   string
	suffix     string
}

func parseMktemp(args []string) (mktempOptions, error) {
	var o mktempOptions
	sawTemplate := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if len(args[i+1:]) > 1 || (sawTemplate && len(args[i+1:]) > 0) {
				return o, fmt.Errorf("too many templates")
			}
			if len(args[i+1:]) == 1 {
				o.template = args[i+1]
				sawTemplate = true
			}
			return o, nil
		case a == "-d" || a == "--directory":
			o.directory = true
		case a == "-u" || a == "--dry-run":
			o.dryRun = true
		case a == "-q" || a == "--quiet":
			o.quiet = true
		case a == "-p" || a == "--tmpdir":
			if i+1 >= len(args) {
				return o, fmt.Errorf("option %s requires an argument", a)
			}
			i++
			o.useTempDir = true
			o.tempDir = args[i]
		case strings.HasPrefix(a, "--tmpdir="):
			o.useTempDir = true
			o.tempDir = strings.TrimPrefix(a, "--tmpdir=")
		case a == "-t":
			o.useTempDir = true
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				o.template = args[i]
				sawTemplate = true
			}
		case a == "--suffix":
			if i+1 >= len(args) {
				return o, fmt.Errorf("option %s requires an argument", a)
			}
			i++
			o.suffix = args[i]
		case strings.HasPrefix(a, "--suffix="):
			o.suffix = strings.TrimPrefix(a, "--suffix=")
		case strings.HasPrefix(a, "-") && len(a) > 2 && !strings.HasPrefix(a, "--"):
			for _, flag := range a[1:] {
				switch flag {
				case 'd':
					o.directory = true
				case 'u':
					o.dryRun = true
				case 'q':
					o.quiet = true
				default:
					return o, fmt.Errorf("unknown option -%c", flag)
				}
			}
		case strings.HasPrefix(a, "-"):
			return o, fmt.Errorf("unknown option %s", a)
		default:
			if sawTemplate {
				return o, fmt.Errorf("too many templates")
			}
			o.template = a
			sawTemplate = true
		}
	}
	return o, nil
}

// mktempPattern turns the final run of at least three Xs into the star used by
// os.CreateTemp. A prefix without Xs is accepted for BSD's -t form.
func mktempPattern(template string) (string, error) {
	end := strings.LastIndexByte(template, 'X') + 1
	start := end
	for start > 0 && template[start-1] == 'X' {
		start--
	}
	if end == 0 {
		return template + ".*", nil
	}
	if end-start < 3 {
		return "", fmt.Errorf("template must contain at least 3 consecutive Xs")
	}
	return template[:start] + "*" + template[end:], nil
}

package tool

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/command"
)

// Base64 implements GNU's common encode/decode forms plus BSD's -D decode
// alias. Encoded output wraps at 76 columns unless -w 0 is requested.
func Base64(next interp.ExecHandlerFunc) interp.ExecHandlerFunc {
	return func(ctx context.Context, args []string) error {
		if len(args) == 0 || filepath.Base(args[0]) != "base64" {
			return next(ctx, args)
		}
		hc := interp.HandlerCtx(ctx)
		parsed := command.Parse(args)
		params, ok := parsed.TypedParams().(command.Base64Params)
		if !ok {
			return Failf(hc.Stderr, 1, "base64: could not parse arguments")
		}
		if len(parsed.Operands) > 1 {
			return Failf(hc.Stderr, 1, "base64: extra operand %q", parsed.Operands[1])
		}

		in := hc.Stdin
		var file *os.File
		if params.File != "" && params.File != "-" {
			name := params.File
			if !filepath.IsAbs(name) {
				name = filepath.Join(hc.Dir, name)
			}
			var err error
			file, err = os.Open(name)
			if err != nil {
				return Failf(hc.Stderr, 1, "base64: %s: %v", params.File, fileError(err))
			}
			defer file.Close()
			in = file
		}
		in = &contextReader{ctx: ctx, r: in}
		if params.Decode {
			if params.IgnoreGarbage {
				in = &base64FilterReader{r: in}
			}
			if _, err := io.Copy(hc.Stdout, base64.NewDecoder(base64.StdEncoding, in)); err != nil {
				return Failf(hc.Stderr, 1, "base64: invalid input")
			}
			return nil
		}

		width := 76
		if params.Wrap != "" {
			var err error
			width, err = strconv.Atoi(params.Wrap)
			if err != nil || width < 0 {
				return Failf(hc.Stderr, 1, "base64: invalid wrap size: %s", params.Wrap)
			}
		}
		out := &lineWrapWriter{w: hc.Stdout, width: width}
		encoder := base64.NewEncoder(base64.StdEncoding, out)
		_, copyErr := io.Copy(encoder, in)
		closeErr := encoder.Close()
		if copyErr != nil {
			return Failf(hc.Stderr, 1, "base64: %v", copyErr)
		}
		if closeErr != nil {
			return Failf(hc.Stderr, 1, "base64: %v", closeErr)
		}
		if _, err := fmt.Fprintln(hc.Stdout); err != nil {
			return interp.ExitStatus(1)
		}
		return nil
	}
}

type lineWrapWriter struct {
	w     io.Writer
	width int
	col   int
}

func (w *lineWrapWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if w.width > 0 && w.col == w.width {
			if _, err := io.WriteString(w.w, "\n"); err != nil {
				return written, err
			}
			w.col = 0
		}
		n := len(p)
		if w.width > 0 && n > w.width-w.col {
			n = w.width - w.col
		}
		m, err := w.w.Write(p[:n])
		written += m
		w.col += m
		p = p[m:]
		if err != nil {
			return written, err
		}
		if m != n {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

type base64FilterReader struct {
	r   io.Reader
	buf []byte
}

func (r *base64FilterReader) Read(p []byte) (int, error) {
	if len(r.buf) < len(p) {
		r.buf = make([]byte, len(p))
	}
	for {
		n, err := r.r.Read(r.buf[:len(p)])
		out := 0
		for _, b := range r.buf[:n] {
			if isBase64Byte(b) {
				p[out] = b
				out++
			}
		}
		if out > 0 || err != nil {
			return out, err
		}
	}
}

func isBase64Byte(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || strings.ContainsRune("+/=\r\n", rune(b))
}

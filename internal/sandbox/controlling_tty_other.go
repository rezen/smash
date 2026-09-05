//go:build !unix

package sandbox

import (
	"os"

	"mvdan.cc/sh/v3/interp"
)

func controllingTTYMiddleware(_ *os.File) Middleware {
	return func(next interp.ExecHandlerFunc) interp.ExecHandlerFunc { return next }
}

func controllingTTYOpenMiddleware(_ *os.File) OpenMiddleware {
	return func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc { return next }
}

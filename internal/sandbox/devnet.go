package sandbox

// Raw sockets. curl/wget aren't the only way out — bash can open a socket
// directly with `/dev/tcp/HOST/PORT` or `/dev/udp/HOST/PORT` (e.g.
// `exec 3<>/dev/tcp/1.2.3.4/4444`), which would slip past httpMiddleware
// entirely. Those are *file opens*, so every one flows through the OpenHandler
// and is caught here.

import (
	"context"
	"fmt"
	"io"
	"os"

	"mvdan.cc/sh/v3/interp"

	"github.com/rezen/smash/internal/network"
)

// netDetectOpenMiddleware logs and denies any /dev/tcp or /dev/udp open.
//
// To ALLOW an allow-listed endpoint instead, dial it and return the net.Conn
// (it is an io.ReadWriteCloser):
//
//	d := net.Dialer{Timeout: 10 * time.Second}
//	return d.DialContext(ctx, proto, net.JoinHostPort(host, port))
func netDetectOpenMiddleware(log io.Writer) OpenMiddleware {
	return func(next interp.OpenHandlerFunc) interp.OpenHandlerFunc {
		return func(ctx context.Context, name string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if proto, host, port, ok := network.ParseDevNet(name); ok {
				fmt.Fprintf(log, "[sandbox] %s socket attempt detected: %s:%s (denied)\n", proto, host, port)
				return nil, fmt.Errorf("%s: [sandbox] raw network device access denied", name)
			}
			return next(ctx, name, flag, perm)
		}
	}
}

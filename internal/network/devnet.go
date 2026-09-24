package network

import (
	"path"
	"strings"
)

// ParseDevNet recognises bash's /dev/tcp and /dev/udp pseudo-device paths —
// `exec 3<>/dev/tcp/HOST/PORT` opens a socket with no command involved, so a
// sandbox must ask this of every file it is told to open.
func ParseDevNet(name string) (proto, host, port string, ok bool) {
	name = path.Clean(name)
	for _, pr := range [...]string{"tcp", "udp"} {
		if rest, found := strings.CutPrefix(name, "/dev/"+pr+"/"); found {
			if h, p, ok := strings.Cut(rest, "/"); ok && h != "" && p != "" && !strings.Contains(p, "/") {
				return pr, h, p, true
			}
		}
	}
	return "", "", "", false
}

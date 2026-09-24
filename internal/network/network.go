// Package network is the one place both sides of the profile/enforce
// boundary get their network mechanics from: the DNS-pinned HTTP client
// in-process fetches ride, host extraction from the target strings commands
// take, and bash's /dev/tcp pseudo-device paths. Host extraction in
// particular must be shared byte-for-byte — the manifest Profiler records
// the hosts a run touched with HostFromEndpoint, and Policy.AllowsTarget
// later matches targets against that recorded list with the same function.
// Two hand-kept copies of the parsing (ports, IPv6 brackets, userinfo,
// trailing dots) would let the halves drift apart, and a drifted pair fails
// closed but inexplicably: a profiled manifest starts denying hosts it just
// recorded.
//
// Host results are canonical: lower-case, no trailing dot, no port, no
// userinfo. What may be REACHED is not decided here; that is sandbox.Policy.
package network

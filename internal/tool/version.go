package tool

// curl/wget version and help probes are answered in-process: the tools are
// served by this package, so the host binary's banner would describe the
// wrong implementation — and a probe must not fail with "no URL specified"
// (installers branch on it, e.g. vector.sh sniffs `wget -V` for BusyBox).

// versionBanner is the tool's --version/-V output. The first line keeps the
// real tool's shape so version-parsing scripts keep working, and names the
// in-process implementation.
func versionBanner(name string) string {
	if name == "curl" {
		return "curl 8.7.1 (smash in-process) libcurl/8.7.1\n" +
			"Protocols: http https\n" +
			"Features: sandboxed in-process subset\n"
	}
	return "GNU Wget 1.21.4 (smash in-process)\n" +
		"Sandboxed in-process subset of wget.\n"
}

// helpText is the tool's --help/-h output: the flags this implementation
// actually honours.
func helpText(name string) string {
	if name == "curl" {
		return "Usage: curl [options...] <url>\n" +
			"Sandboxed in-process curl. Supported options:\n" +
			" -s, -S, -f, -L, -I, -O, -o <file>, -X <method>, -H <header>,\n" +
			" -A <agent>, -e <referer>, -b <cookie>, -d/--data <data>,\n" +
			" --data-raw, --data-binary, --data-urlencode, -w <format>, --url <url>\n"
	}
	return "Usage: wget [options...] <url>\n" +
		"Sandboxed in-process wget. Supported options:\n" +
		" -q, -O <file>, -U <agent>, --header <header>\n"
}

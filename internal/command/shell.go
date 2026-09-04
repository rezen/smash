package command

import "strings"

// Shell is both a plain command and a ScriptRunner (for `sh -c 'SCRIPT'`).
type Shell struct{}

var shellSpec = Spec{ValueFlags: NewSet("-c")}

func (Shell) Names() []string                              { return []string{"sh", "bash", "dash", "ash"} }
func (Shell) Parse(a []string) ParsedCommand               { return shellSpec.Parse(a) }
func (Shell) DashC(args []string) (string, []string, bool) { return extractDashC(args) }

// extractDashC finds a `-c SCRIPT` (also in clustered flags like `-euc`) and
// returns the script plus any trailing positional params ($0, $1, …).
func extractDashC(args []string) (script string, params []string, ok bool) {
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return "", nil, false
		case a != "-" && strings.HasPrefix(a, "-"):
			if strings.ContainsRune(a, 'c') { // -c, -ec, -euc, …
				if i+1 >= len(args) {
					return "", nil, false
				}
				return args[i+1], args[i+2:], true
			}
			// other option flag (-e, -u, …): keep scanning
		default:
			return "", nil, false // a non-flag before -c ⇒ `sh file …`, not `-c`
		}
	}
	return "", nil, false
}

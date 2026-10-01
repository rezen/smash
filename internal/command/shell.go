package command

import "strings"

// Shell is both a plain command and a ScriptRunner (for `sh -c 'SCRIPT'`).
type Shell struct{}

func (Shell) Names() []string { return []string{"sh", "bash", "dash", "ash"} }
func (Shell) Parse(a []string) ParsedCommand {
	s := parseShellArgv(a)
	p := ParsedCommand{Flags: map[string][]string{}, raw: a}
	for _, opt := range s.opts {
		p.Flags[opt] = append(p.Flags[opt], "")
	}
	if s.hasC && s.script != "" {
		p.Flags["-c"] = []string{s.script}
		p.Operands = append(p.Operands, s.params...)
	} else if s.file != "" {
		p.Operands = append([]string{s.file}, s.params...)
	}
	return p
}
func (Shell) DashC(args []string) (string, []string, bool) {
	s := parseShellArgv(args)
	return s.script, s.params, s.hasC && s.script != ""
}

type shellArgv struct {
	script string
	params []string
	opts   []string
	file   string
	hasC   bool
}

func parseShellArgv(args []string) (s shellArgv) {
	if len(args) == 0 {
		return s
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			if i+1 < len(args) {
				if s.hasC {
					s.script = args[i+1]
				} else {
					s.file = args[i+1]
				}
				s.params = args[i+2:]
			}
			return s
		case a == "--rcfile" || a == "--init-file":
			i++
		case strings.HasPrefix(a, "--"):
			continue
		case len(a) > 1 && (a[0] == '-' || a[0] == '+'):
			for _, c := range a[1:] {
				if c == 'c' && a[0] == '-' {
					s.hasC = true
				}
				if c == 'o' {
					i++
					break
				}
				s.opts = append(s.opts, string(a[0])+string(c))
			}
		default:
			if s.hasC {
				s.script = a
			} else {
				s.file = a
			}
			s.params = args[i+1:]
			return s
		}
	}
	return s
}

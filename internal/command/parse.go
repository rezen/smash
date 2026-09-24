package command

import "strings"

// Spec is a declarative flag specification: which flags take a separate value,
// whether short flags cluster (curl's -fsSL), and whether the first operand
// names a subcommand (openssl/git). Its Parse is the generic argv parser that
// every Command ultimately uses.
type Spec struct {
	ValueFlags   Set
	ClusterShort bool
	Subcommand   bool
	// StopAtOperand ends flag parsing at the first operand (after the
	// subcommand, if any), POSIX-style, so everything after it is an operand
	// even if it starts with "-". ssh and perl behave this way: `ssh host ls -a`
	// sends -a to the remote command.
	StopAtOperand bool
	// AttachedValue flags take an optional value only when it is glued on:
	// `sed -i.bak` is -i with suffix ".bak", `sed -i s/a/b/` is a bare -i.
	AttachedValue Set
}

// Parse splits args[1:] into flags and operands according to the spec.
func (o Spec) Parse(args []string) ParsedCommand {
	p := ParsedCommand{Flags: map[string][]string{}, raw: args, attached: o.AttachedValue}
	if len(args) == 0 {
		return p
	}
	rest := args[1:]
	wantSub := o.Subcommand // the first operand names the subcommand (`apt-get -y install foo`)
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--":
			p.Operands = append(p.Operands, rest[i+1:]...)
			return p
		case a == "-" || !strings.HasPrefix(a, "-"):
			if wantSub {
				p.Subcommand, wantSub = a, false
				p.subIndex = i + 1 // its index in args (rest starts at args[1])
				continue
			}
			if o.StopAtOperand {
				p.Operands = append(p.Operands, rest[i:]...)
				return p
			}
			p.Operands = append(p.Operands, a)
		case strings.HasPrefix(a, "--"):
			name, val, hasEq := strings.Cut(a, "=")
			switch {
			case hasEq:
				p.Flags[name] = append(p.Flags[name], val)
			case o.ValueFlags[name] && i+1 < len(rest):
				p.Flags[name] = append(p.Flags[name], rest[i+1])
				i++
			default:
				p.Flags[name] = append(p.Flags[name], "")
			}
		default:
			if o.ClusterShort && len(a) > 2 && !o.ValueFlags[a] {
				i += o.parseShortCluster(&p, a, rest, i)
			} else if o.ValueFlags[a] && i+1 < len(rest) {
				p.Flags[a] = append(p.Flags[a], rest[i+1])
				i++
			} else {
				p.Flags[a] = append(p.Flags[a], "")
			}
		}
	}
	return p
}

// parseShortCluster expands -fsSL, where a trailing value flag (e.g. -o in -sSo)
// takes the rest or the next arg, and an attached-value flag takes the rest
// only. Returns extra args consumed (0 or 1).
func (o Spec) parseShortCluster(p *ParsedCommand, a string, rest []string, i int) int {
	chars := a[1:]
	for j := 0; j < len(chars); j++ {
		fl := "-" + string(chars[j])
		if o.AttachedValue[fl] {
			p.Flags[fl] = append(p.Flags[fl], chars[j+1:])
			return 0
		}
		if o.ValueFlags[fl] {
			if val := chars[j+1:]; val != "" {
				p.Flags[fl] = append(p.Flags[fl], val)
				return 0
			}
			if i+1 < len(rest) {
				p.Flags[fl] = append(p.Flags[fl], rest[i+1])
				return 1
			}
			p.Flags[fl] = append(p.Flags[fl], "")
			return 0
		}
		p.Flags[fl] = append(p.Flags[fl], "")
	}
	return 0
}

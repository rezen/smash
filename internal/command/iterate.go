package command

import (
	"strconv"
	"strings"
)

func (Find) Plan(p ParsedCommand) (Iteration, bool) {
	fp := findParamsFrom(p.Argv())
	expr := fp.Expression
	start, end := -1, -1
	otherAction := false
	var action string
	for i, a := range expr {
		switch a {
		case "-exec", "-execdir", "-ok", "-okdir":
			if start >= 0 {
				return Iteration{}, false
			}
			start, action = i, a
		case "-delete", "-print", "-print0":
			otherAction = true
		}
	}
	if start < 0 || otherAction {
		return Iteration{}, false
	}
	for i := start + 1; i < len(expr); i++ {
		if expr[i] == ";" || expr[i] == "+" {
			end = i
			break
		}
	}
	if end < 0 || end == start+1 {
		return Iteration{}, false
	}
	for _, a := range expr[end+1:] {
		switch a {
		case "-exec", "-execdir", "-ok", "-okdir", "-delete", "-print", "-print0":
			return Iteration{}, false
		}
	}
	driver := append([]string(nil), p.Argv()[:len(p.Argv())-len(expr)]...)
	driver = append(driver, expr[:start]...)
	driver = append(driver, "-print0")
	driver = append(driver, expr[end+1:]...)
	batch := 1
	if expr[end] == "+" {
		batch = 0
	}
	if action == "-execdir" || action == "-okdir" {
		batch = 1
	}
	return Iteration{Driver: driver, Template: append([]string(nil), expr[start+1:end]...), Placeholder: "{}", Batch: batch, NUL: true, Dir: action == "-execdir" || action == "-okdir"}, true
}

func (Xargs) Plan(p ParsedCommand) (Iteration, bool) {
	a := p.Argv()
	it := Iteration{Batch: 0, RunEmpty: true}
	if len(a) == 0 {
		return it, false
	}
	i := 1
	for i < len(a) {
		v := a[i]
		if v == "--" {
			i++
			break
		}
		if !strings.HasPrefix(v, "-") || v == "-" {
			break
		}
		name, value, hasEq := strings.Cut(v, "=")
		if !hasEq && len(v) > 2 && v[0] == '-' && v[1] != '-' && strings.ContainsRune("nLIPda", rune(v[1])) {
			name, value, hasEq = v[:2], v[2:], true
		}
		take := func() (string, bool) {
			if hasEq {
				return value, true
			}
			if len(name) > 2 && name[0] == '-' && name[1] != '-' {
				return name[2:], true
			}
			if i+1 >= len(a) {
				return "", false
			}
			i++
			return a[i], true
		}
		switch {
		case v == "-0" || v == "--null":
			it.NUL = true
		case v == "-r" || v == "--no-run-if-empty":
			it.RunEmpty = false
		case v == "-t" || v == "--verbose":
			it.Trace = true
		case v == "-i":
			it.Placeholder, it.Batch = "{}", 1
		case strings.HasPrefix(v, "-i") && len(v) > 2:
			it.Placeholder, it.Batch = v[2:], 1
		case name == "-I" || name == "--replace":
			val, ok := take()
			if !ok {
				return Iteration{}, false
			}
			it.Placeholder, it.Batch = val, 1
		case name == "-n" || name == "--max-args" || name == "-L" || name == "--max-lines":
			val, ok := take()
			if !ok {
				return Iteration{}, false
			}
			n, err := strconv.Atoi(val)
			if err != nil || n <= 0 {
				return Iteration{}, false
			}
			it.Batch = n
		case name == "-a" || name == "--arg-file":
			val, ok := take()
			if !ok {
				return Iteration{}, false
			}
			it.ArgFile = val
		case name == "-d" || name == "--delimiter":
			val, ok := take()
			if !ok || val == "" {
				return Iteration{}, false
			}
			it.Delimiter = val[:1]
		case name == "-P" || name == "--max-procs":
			if _, ok := take(); !ok {
				return Iteration{}, false
			}
		default:
			return Iteration{}, false
		}
		i++
	}
	it.Template = append([]string(nil), a[i:]...)
	if len(it.Template) == 0 {
		it.Template = []string{"echo"}
	}
	return it, true
}

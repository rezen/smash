// Package shell holds the mechanics of hosting a shell script that decide
// no policy: what a script's `#!` line names, and the terminal plumbing a
// script facing a real TTY needs. The shebang answer is one answer shared by
// everything that asks — the POSIX-mode check on a script's source (IsSh)
// and the interpreter check on an in-root file the sandbox's command gate is
// about to judge (InterpreterFromFile) must agree on what a shebang names,
// env indirection included.
package shell

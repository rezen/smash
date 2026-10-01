package sandbox

import (
	"context"
	"maps"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Session preserves variables, functions, aliases, options and cwd between
// batches. Calls to Run must be serial; commands within a batch may be concurrent.
type Session struct {
	cfg    Config
	runner *interp.Runner
}

// NewSession builds one runner. Unlike Run, a zero Timeout means no deadline.
func NewSession(cfg Config) (*Session, error) {
	timeout := cfg.Timeout
	cfg = cfg.normalized()
	cfg.Timeout = timeout
	cfg, runner, err := prepareRunner(cfg)
	if err != nil {
		return nil, err
	}
	return &Session{cfg: cfg, runner: runner}, nil
}

func (s *Session) Run(ctx context.Context, stmts []*syntax.Stmt) error {
	if s.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Timeout)
		defer cancel()
	}
	prog := &syntax.File{Name: "repl", Stmts: stmts}
	rewriteSubshellReturns(prog)
	return s.runner.Run(ctx, prog)
}

func (s *Session) Exited() bool { return s.runner.Exited() }
func (s *Session) Vars() Vars   { return Vars(maps.Clone(s.runner.Vars)) }

package command

import (
	"context"
	"slices"
)

type parsedKey struct{}

// WithParsed carries one parse through the execution stack.
func WithParsed(ctx context.Context, p ParsedCommand) context.Context {
	return context.WithValue(ctx, parsedKey{}, p)
}

// ParsedFrom returns the cached parse when it belongs to args.
func ParsedFrom(ctx context.Context, args []string) (ParsedCommand, bool) {
	p, ok := ctx.Value(parsedKey{}).(ParsedCommand)
	return p, ok && slices.Equal(p.Argv(), args)
}

// Package approve implements external command approval over Connect RPC.
package approve

import (
	"errors"

	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"github.com/rezen/smash/internal/command"
	"github.com/rezen/smash/internal/sandbox"
	"mvdan.cc/sh/v3/interp"
)

const Version = 1

func resources(rs []command.Resource) []*approvev1.Resource {
	out := make([]*approvev1.Resource, 0, len(rs))
	for _, r := range rs {
		out = append(out, &approvev1.Resource{Kind: r.Kind, Action: r.Action, Value: r.Value})
	}
	return out
}
func files(fs []command.FileChange) []*approvev1.FileChange {
	out := make([]*approvev1.FileChange, 0, len(fs))
	for _, f := range fs {
		out = append(out, &approvev1.FileChange{Op: string(f.Op), Path: f.Path, From: f.From, Recursive: f.Recursive})
	}
	return out
}
func egress(e *command.Egress) *approvev1.Egress {
	if e == nil {
		return nil
	}
	return &approvev1.Egress{Target: e.Target, Kind: uint32(e.Kind)}
}
func requestCommand(r sandbox.ApprovalRequest) *approvev1.Command {
	return &approvev1.Command{Name: r.Name, Argv: r.Argv, Line: r.Line, Wrappers: r.Wrappers, Resources: resources(r.Resources), Egress: egress(r.Egress), Files: files(r.Files), Verdict: r.Verdict.String()}
}

// auditRecord converts error and Params interfaces to explicit wire fields.
func auditRecord(r sandbox.AuditRecord) *approvev1.AuditRecord {
	d := &approvev1.AuditRecord{Name: r.Name, Command: r.Command, Resources: resources(r.Resources), Egress: egress(r.Egress), Served: r.Served, Files: files(r.Files), Reason: r.Reason, ContentType: r.ContentType, Sniffed: r.Sniffed, Via: r.Via, Wrappers: r.Wrappers, Unlisted: r.Unlisted, InRoot: r.InRoot, DurationMs: r.Duration.Milliseconds()}
	if r.Params != nil {
		d.Params = r.Params.String()
	}
	if r.Exit != nil {
		if code, ok := errors.AsType[interp.ExitStatus](r.Exit); ok {
			d.Exit = int32(code)
		} else {
			d.Exit = 1
			d.Error = r.Exit.Error()
		}
	}
	return d
}

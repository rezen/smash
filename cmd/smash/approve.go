package main

import (
	"context"
	"fmt"
	approvev1 "github.com/rezen/smash/gen/smash/approve/v1"
	"net/http"
	"os"
	"time"

	"github.com/rezen/smash/internal/approve"
	"github.com/rezen/smash/internal/policy"
	"github.com/rezen/smash/internal/sandbox"
	"golang.org/x/term"
)

func approvalSettings(pol *policy.File, fl *cliFlags) (string, time.Duration, http.Header) {
	address, timeout := "", 60*time.Second
	headers := make(http.Header)
	if p := pol.Approve; p != nil {
		address = p.URL
		if p.Timeout != nil {
			timeout = time.Duration(*p.Timeout)
		}
		for k, v := range p.Headers {
			headers.Set(k, v)
		}
	}
	if fl.set["approve"] {
		address = fl.approve
	}
	if fl.set["approve-timeout"] {
		timeout = fl.approveTimeout
	}
	return address, timeout, headers
}
func wireApprover(pol *policy.File, fl *cliFlags, cfg *sandbox.Config) (func(), error) {
	address, timeout, headers := approvalSettings(pol, fl)
	cleanup := func() {}
	if address == "" {
		return cleanup, nil
	}
	cfg.ApproveTimeout = timeout
	if address == "prompt" {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return cleanup, fmt.Errorf("approve prompt needs a controlling terminal: %w", err)
		}
		if !term.IsTerminal(int(tty.Fd())) {
			tty.Close()
			return cleanup, fmt.Errorf("approve prompt needs a terminal")
		}
		cfg.Approver = approve.NewPrompt(tty, tty)
		return func() { tty.Close() }, nil
	}
	mode, _ := effectiveMode(pol, fl)
	client, err := approve.Dial(context.Background(), address, approve.Options{Timeout: timeout, Headers: headers, Stderr: os.Stderr, Hello: &approvev1.OpenSessionRequest{Root: cfg.Root, Mode: mode, Interactive: fl.interactive}})
	if err != nil {
		return cleanup, err
	}
	cfg.Approver = client
	cfg.ApproveTimeout = client.Timeout()
	return func() { client.Close() }, nil
}
func attachApproverAudit(cfg *sandbox.Config) {
	if c, ok := cfg.Approver.(*approve.Client); ok && c.AuditEnabled() {
		cfg.Auditor = sandbox.MultiAuditor(cfg.Auditor, approve.AuditSink{Client: c})
	}
}

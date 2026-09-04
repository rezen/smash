# Layout

```
fixtures/uv-installer.sh     vendored uv installer (offline install test; primary test case)
fixtures/rvm-installer       vendored rvm installer (heavier stress test)
fixtures/get-docker          vendored Docker install script (Linux-emulation test)
fixtures/fly.sh              vendored Fly.io installer (mocked-network audit-trail test; CLI example)
fixtures/aqua.sh             vendored trivy installer (godownloader skeleton; mocked-network test)
fixtures/bearer.sh           vendored Bearer installer (godownloader skeleton; mocked-network test)
fixtures/truffle.sh          vendored trufflehog installer (godownloader skeleton; mocked-network test)
fixtures/cursor.sh           vendored Cursor agent installer (streamed curl | tar; mocked-network test)
fixtures/php.sh              vendored php.new installer (backgrounded downloads; mocked-network test)
fixtures/warp.sh             vendored Warp agent CLI installer (noclobber lock, redirect probe; mocked-network test)
fixtures/nvm.sh              vendored nvm installer (script mode completes; git mode held by the egress guard)
fixtures/terragrunt.sh       vendored Terragrunt installer (GPG verification path; errexit patch)
fixtures/brew-install.sh     vendored Homebrew installer (Linux-emulation containment test)
fixtures/starship.sh         vendored Starship installer (POSIX-sh guard; mocked-network test)
cmd/smash/main.go            the CLI: run a local or remote install script under a policy

internal/policy/    the YAML policy file (-policy, -init-policy)
  policy.go     File + Load/Parse (strict: unknown keys rejected) + Apply onto a sandbox.Config
  template.go   Template — the commented boilerplate -init-policy writes

internal/command/   the command model (pure; no interp dependency)
  command.go    Command + capability interfaces, ParsedCommand
  registry.go   Registry (duplicate names rejected), Default, Set
  parse.go      Spec — the generic argv parser
  network.go    Curl/Wget/Openssl/SSH/Scp/Rsync/Netcat/Git/Perl/Python, Request + Downloader
  shell.go      Shell + `-c` extraction
  wrappers.go   PrefixWrapper, Xargs, Unwrap
  builtins.go   Tool + the safe local tools, Grep/Sed/Awk/Tar/Base64/Find
  perms.go      chmod/chown/chgrp/chattr/setfacl/chflags/chcon/install (PathMutator)
  fileops.go    FileChange/FileOperator; rm/mv/cp/ln/mkdir/mktemp/tee/unzip/gzip/dd (monitoring)
  nettools.go   NetTool — the data-driven long tail of network tools; Gpg
  params.go     typed, reversible params (CurlParams, FindParams, …)
  resource.go   Resource + Describe: what an invocation touches, for audit logs
  redact.go     Redact: secret fields/flags replaced before anything is logged
  describe.go   Describer implementations (grep/sed/awk/tar, find, sh, install, …)
  packages.go   PackageManager — apt/yum/apk/brew/pip/npm/cargo/… by subcommand
  bind.go       tag-driven bind/render/spec derivation for params structs

internal/sandbox/   the enforcement stack on mvdan/sh
  sandbox.go    Config, NewConfig, Run, buildRunner
  audit.go      AuditRecord, Auditor, TextAuditor, stdin/stdout capture (Config.Auditor/AuditData)
  control.go    Disable (deny-list) and Mock + Matchers (canned stdout/stderr/exit)
  allowlist.go  DefaultAllowList + DefaultSensitiveList + the command gate (unlisted runs audited; Strict) / in-sandbox escape hatch, shebang-aware
  middleware.go unwrap (+ the wrapper chain for the audit record) + sleep cap
  shinterp.go   confined interpretation of `sh -c` and of in-root shell scripts
  network.go    Policy (structural URL matching), in-process curl/wget (net/http), egress guard
  devnet.go     /dev/tcp + /dev/udp detection
  detection.go  CallHandler shims (downloader probe, typeset compat)
  emulate.go    Emulation: fake uname + virtual files
  fixups.go     AST rewrites where mvdan/sh and bash differ (subshell `return`)
  vars.go       RunVars (resolved variable table) + Assignments (static AST walk)
  *_test.go     egress, unwrap, redirects, rvm/get-docker containment
```

# Patches to mvdan.cc/sh/v3

`third_party/sh` is a generated, untracked copy of `mvdan.cc/sh/v3` at the
version required in the root `go.mod`, trimmed to the packages smash imports
(`expand`, `fileutil`, `internal`, `interp`, `pattern`, `syntax`) with tests
and testdata removed, plus the patch in this directory. The root `go.mod`
points at it with

    replace mvdan.cc/sh/v3 => ./third_party/sh

Regenerate it with either of

    go generate ./...
    sh tools/sync-sh.sh

A fresh clone will not build until this has run once. The upstream licence
(`third_party/sh/LICENSE`) applies to the generated tree.

`handlerctx.patch` is a one-hunk diff against `interp/handler.go`; see Patch 7.
`smash.patch` is a single unified diff against `interp/api.go`,
`interp/runner.go`, `interp/test.go` and `expand/param.go` (the logical changes below share
hunks, so they are not split). Every hunk is marked `smash patch` in the
source.

## Patch 1: file descriptors beyond 0/1/2

Upstream `interp` only knows stdin, stdout and stderr; any redirection naming
another descriptor fails with `unsupported redirect fd: N` (`interp/runner.go`,
`Runner.redir`). Installers use extra descriptors routinely — nvm's version
lookup is the classic swap `{ v="$(f 3>&1 1>&4)"; } 4>&1`, and it discards fd 3
with `f 3>/dev/null`.

The patch adds to `Runner`:

- `extraOut map[string]io.Writer` and `extraIn map[string]stdinFile`: the
  shell's descriptor table for fds ≥ 3 (`interp/api.go`).
- `getOut/setOut/getIn/setIn` (`interp/runner.go`): fd 0/1/2 map to the
  existing fields, anything else to the maps.
- `Runner.redir` accepts any numeric fd. `N>file`, `N>>file`, `N<file` open
  into slot N; `N>&M` and `N<&M` duplicate slot M into N and fail with
  `M: Bad file descriptor` when M is not open, as bash does; `N>&-`/`N<&-`
  close N.
- `stmtSync` saves and restores the two maps around a statement's
  redirections, exactly as it already does for stdin/stdout/stderr, and honours
  `exec` (`keepRedirs`) the same way. `Runner.sub` clones them into subshells
  and command substitutions.

Not covered: the extra descriptors are visible only to the shell itself
(builtins, functions, subshells). Exec'd commands still receive just
stdin/stdout/stderr, so `external-cmd >&3` writes go to the descriptor from the
shell's side (the handler's Stdout is the fd-3 writer), but a child that opens
`/dev/fd/3` itself will not find it.

## Patch 2: `noclobber` and `>|`

Upstream rejects `set -o noclobber` / `set -C` ("set: invalid option") and the
`>|` redirection ("unhandled redirect op"). Under `set -e` the rejected `set`
aborts the subshell, so warp's exclusive-create lock
`(set -o noclobber; printf owner > lock) 2>/dev/null` fails every time.

- `posixOptsTable` gains `{'C', "noclobber"}` and the option enum
  `optNoClobber` (`interp/api.go`); `$-` reports `C` like bash.
- `Runner.redir`: with the option on, `>` and `&>` open with `O_EXCL` instead
  of `O_TRUNC` and fail with `NAME: cannot overwrite existing file`; `>|`
  always truncates (`interp/runner.go`).

`TestNoclobber` in `internal/sandbox` pins it.

## Patch 3: errexit and compound bodies

Upstream `stmt` re-judges `set -e` on every statement's exit status, including
a compound command's — and a compound's status is that of the last statement
in its body. So an errexit-exempt failure in last position, such as
terragrunt's

    if [[ -n "$VERIFY_SIG" ]]; then
        …
        ! supports_signature_verification "$version" && warn "…"
    fi

exits the script at the `fi`, where bash carries on. bash judges only the
statement itself: `if`/`{ }`/`for`/`while`/`case` bodies inherit their last
statement's exemption, while a failing function call, subshell or command
substitution is a command of its own and still exits.

- `isBodyCompound` (`interp/runner.go`) names those five clause types, and
  `stmt` skips the errexit/ERR-trap branch for them. The statements inside the
  body have already made that decision for themselves.

`TestErrexitCompoundBodies` in `internal/sandbox` pins it; every case was
checked against `/bin/bash`.

## Patch 4: `set -u` and unused expansion words

Upstream `paramExp` (`expand/param.go`) expands the word of `${v-w}`,
`${v+w}`, `${v?w}`, `${v=w}` and their `:` variants before deciding whether
the word is used. Under `set -u` that trips `nounset` on an unset variable
inside a word bash never evaluates — ollama's

    VER_PARAM="${OLLAMA_VERSION:+?version=$OLLAMA_VERSION}"

died with `OLLAMA_VERSION: unbound variable` although bash, with the variable
unset, skips the word entirely.

- `paramExp` decides per operator whether the word is used (`+`: set;
  `:+`: set and non-null; `-`/`?`/`=`: unset; `:-`/`:?`/`:=`: unset or
  null) and only then calls `Literal` on it.
- `perElemOps`, the `${arr[@]…}` path, expands the word only for the
  pattern-removal and case-conversion operators that actually use it.

`TestNounsetUnusedWord` in `internal/sandbox` pins it; every case was checked
against `/bin/bash`.

## Patch 5: `[[ ]]` short-circuits `&&` and `||`

Upstream `bashTest` (`interp/test.go`) expands and evaluates both operands of
a `&&`/`||` inside `[[ ]]` and only then combines them in `binTest`. bash
short-circuits, so the right operand is never expanded when the left one
decides the result. Under `set -u` that difference is fatal: bun's

    if [[ $# = 2 && $2 = debug-info ]]; then

died with `2: unbound variable` when the script had no arguments.

- `bashTest` handles `AndTest`/`OrTest` itself: it evaluates the left
  operand, returns when that decides the result, and evaluates the right one
  only otherwise. Skipped operands are not expanded, so `$((i++))` side
  effects and `nounset` errors on that side are skipped too, as in bash.

`TestTestClauseShortCircuit` in `internal/sandbox` pins it; every case was
checked against `/bin/bash`.

## Patch 6: `${!name…}` and the operator after it

Upstream `paramExp` (`expand/param.go`) returns the value of a plain
indirection `${!name}` and ignores any operator after it, so bun's

    install_dir=${!install_env:-$HOME/.bun}

expanded to `""` with `$BUN_INSTALL` unset and the installer went on to write
`/bin/bun.zip`. bash applies the operator to the target variable.

- `paramExp` re-targets a plain indirection to the variable named by `$name`
  (including `arr[i]` values) before the operator switch, so `${!name:-w}`,
  `${!name:+w}`, `${!name:1:2}`, `${!name#p}` and `${!name/p/r}` work on
  the target, and under `set -u` an unset target is an unbound variable as in
  bash. `${!prefix*}`, `${!arr[@]}` and namerefs keep their upstream meaning.

`TestIndirectExpansion` in `internal/sandbox` pins it; every case was checked
against `/bin/bash`.

## Patch 7: `WithHandlerContext`

`HandlerContext` travels on the context under an unexported key
(`interp/handler.go`), and `HandlerCtx` only reads it. Middleware that captures
what a command reads and writes has to hand the inner handler a context with
*substituted* streams, which from outside the package was possible only by
answering the lookup for that key by its reflected type name — a coupling that
would have broken silently, at run time, on a resync.

- `WithHandlerContext(ctx, hc)` is the exported constructor, three lines beside
  `HandlerCtx` (`interp/handler.go`).

`TestWithHandlerContext` in `internal/sandbox` pins it, and `auditMiddleware`
now fails to compile rather than silently losing every captured byte if a
resync drops the patch. This one is a candidate to upstream: it is additive and
useful to anyone wrapping a handler.

## Refreshing

To move to a newer upstream: bump the `mvdan.cc/sh/v3` version in the root
`go.mod`, run `sh tools/sync-sh.sh`, and fix any hunk of `smash.patch` that
no longer applies (edit the generated files, then regenerate the patch with
`diff -u` against the pristine module in `$(go env GOMODCACHE)`, using
`--label a/PATH --label b/PATH` so it stays `patch -p1` compatible). Then
`go test ./...` — `TestExtraFileDescriptors`, `TestNoclobber`,
`TestErrexitCompoundBodies`, `TestNounsetUnusedWord`,
`TestTestClauseShortCircuit`, `TestIndirectExpansion` and
`TestWithHandlerContext` in `internal/sandbox` pin the behaviour. Better still, upstream the change:
mvdan/sh tracks this gap as "support file descriptors other than 0, 1, 2".

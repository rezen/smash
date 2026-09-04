# Plan: filesystem state tracking + a "not yours to remove" guard

## Goal

1. **Track filesystem state through a run**: a ledger of every path the
   script created, wrote, appended, deleted, moved, copied, linked or
   extracted, each event tied to the command (audit record) that did it — so
   a run ends with an accurate "what changed on disk" report, not just the
   per-command `files:` guesses derived from argv.
2. **Block removing or moving files the installer did not create**, with the
   same reach the other guards have: through `sudo`, `find -exec`, `xargs`,
   `sh -c`, and the shell's own redirections.

## Core idea: origin, not creation tracking

Trying to catch every *creation* (tar extracts hundreds of files; a freshly
installed `uv` writes wherever it likes) is fragile. Flip it: what we need to
know is which paths were **there before the script started**.

- At `Run` start, snapshot `cfg.Root` (every file, dir, symlink; `Lstat`,
  no following). Those paths have origin **preexisting**.
- Any path **outside** the root is preexisting by definition — we cannot
  enumerate the host, and the script did not create it unless our ledger saw
  it do so.
- Any path inside the root that is *not* in the snapshot was created during
  the run (by whatever means, modelled or not) — origin **created**.

Then the rule the guard enforces is one line:

```
protected(p) = origin(p) == preexisting
             || (p outside root && ledger has no "created" entry for p)
recursive op on p: protected if p or ANY preexisting path under p/ is protected
```

Creation tracking (the ledger) still matters for deliverable 1 and for the
outside-root exception, but the guard's correctness no longer depends on it.

## Data model — `internal/sandbox/files.go` (new)

```go
type Origin int // Preexisting | Created

type FileEvent struct {
    Op        command.FileOp // create/write/append/delete/move/copy/link/extract/mode/…
    From      string         // source for move/copy/link/extract
    Cmd       string         // "rm -rf …" (redacted command line) or "shell" for redirections
    Seq       int            // audit record ordinal, to join with the audit log
    Observed  bool           // found by the reconcile walk, not derived from argv
    Blocked   bool           // the guard refused it (event kept so the attempt is visible)
    Time      time.Time
}

type FileEntry struct {
    Path   string     // absolute, cleaned
    Origin Origin
    Exists bool       // current belief
    Events []FileEvent
}

type FileState struct {           // shared by pointer with sh -c sub-runners
    mu      sync.Mutex             // `curl … &` runs handlers concurrently
    root    string
    entries map[string]*FileEntry
    seq     int
}
```

Operations:

- `snapshot(root)` — the baseline walk (`filepath.WalkDir`, `Lstat`).
- `resolve(hc.Dir, p)` — `Abs` against the **runner's** cwd (`hc.Dir`, which
  is right inside `sh -c` sub-runners and after `cd`), then `Clean`. No
  `EvalSymlinks` on the leaf (`rm link` removes the link, not the target),
  but the *parent* is resolved through symlinks so `mv ~/l/x …` where `~/l →
  ~/.config` is judged as `~/.config/x`.
- `Protected(p, recursive) (why string, bool)` — the rule above; `why` names
  the offending preexisting path (the descendant, for recursive ops).
- `Apply(changes []command.FileChange, cmd, dir)` — after a command **exits
  0**: `delete` → `Exists=false`; `move` → destination entry inherits the
  source's origin (matters in Warn mode) and the source is marked gone;
  `copy`/`link`/`write`/`create`/`touch` → destination is `Created` if new;
  `extract` → no entries, the reconcile walk fills them.
- `Reconcile(cmd)` — walk the root, diff against `entries`: new paths become
  `Created` with an `Observed` event on this command; paths that vanished get
  an `Observed` delete event. **If a vanished path was preexisting, that is a
  violation** (something unmodelled — an in-sandbox binary, `rsync --delete`,
  `xargs rm` fed by stdin — removed it): record it and, in Deny mode, make
  `Run` return `*ProtectedRemovedError` at the end.
- `Report()` — grouped summary: created, modified, appended, deleted, moved,
  copied, linked, blocked attempts, violations. Rendered by `TextAuditor` as
  a trailing `- name: files` YAML item, and available via
  `sandbox.RunFiles(cfg, name, src) (*FileState, error)` (mirrors `RunVars`).

When to reconcile (`FileGuard.Reconcile`): `AfterEveryExec` (default),
`AfterMutators` (skip commands whose parsed form is a read-only `Builtin`
with no `FileChanges` — grep, cat, uname…), or `EndOfRun`. Always once at the
end. Cost is one `Lstat` per path in the root per reconciled command; roots
for installers are tens to low thousands of paths, so this is milliseconds.
Measure with the rvm fixture (the busiest one) before settling the default.

## The guard — `internal/sandbox/fsguard.go` (new)

```go
type GuardMode int // Off | Warn | Deny

type FileGuard struct {
    Mode      GuardMode
    Overwrite bool     // also protect preexisting files from write/truncate:
                       // `> f`, `cp x f`, `sed -i f`, `install … f`, `tee f`, `dd of=f`
                       // (append `>> f` is never blocked: PATH lines in ~/.bashrc are what installers do)
    Allow     []string // path globs exempt from protection, e.g. "~/.cache/**"
    Reconcile ReconcilePolicy
}
```

Config: `cfg.Files FileGuard` (policy) and `cfg.State *FileState` (created by
`Run` when `Mode != Off`; a pointer so `shInterpMiddleware`'s `sub := cfg`
shares it with every nested `sh -c` runner, exactly like `Mocks`).

### Exec middleware `fsMiddleware(state, guard)`

One middleware does pre-check, run, post-apply:

1. Parse, collect `changes := p.FileChanges()`. Also fold in the **outer**
   command's changes when the invocation was unwrapped (see `find` below).
2. For each change, decide what it destroys:
   - `delete` → its `Path` (recursive per the change).
   - `move` → its `From` (always recursive: moving a dir takes the contents),
     **and** its `Path` if that exists (mv clobbers the destination).
   - `link` with `-f`, `copy`, `write`, `extract` onto an existing path → only
     when `guard.Overwrite`.
3. Resolve against `hc.Dir`; if `state.Protected(...)`:
   - **Deny**: `failf(hc.Stderr, 1, "[sandbox] protected path: %s: %s existed before the script ran", p.Name, why)` — a `Failure`, so the audit record carries it as `reason:`. Nothing runs.
   - **Warn**: print `[sandbox] warning: …`, record a `Blocked:false` event, continue.
4. `err := next(ctx, args)`; on `err == nil`, `state.Apply(changes, …)`; then
   `state.Reconcile(...)` per policy (skipped for `ScriptRunner` commands — the
   sub-runner reconciles its own commands).

Position in `buildRunner`: `unwrap → audit → deny → **fs** → mock → sleepcap →
sh -c → … → allow-list`. Inside audit so the refusal is logged with its
reason; before mocks because denial beats mocking (matches `Disable`) and
because a mock's `Respond` can write real files (the tests' fake tarballs) —
those must be reconciled too.

### Open middleware `fsOpenMiddleware(state, guard)`

The shell's own opens never reach the exec chain, so:

- `>` (`O_TRUNC`, or `O_EXCL` under noclobber — that one only creates) on a
  protected existing path → deny with an error when `Overwrite`; else allow.
- `>>` → always allowed.
- Every successful create/write/append is recorded as a `shell` event, so
  `echo … > /tmp/outside-root` makes that path deletable later.

Open chain order (first listed is innermost): `netDetect, virtualOpen,
**fsOpen**, auditOpen` — the audit wrapper stays outermost so the record shows
the denial's error.

## Command-model changes — `internal/command`

- **`find`**: `Find.FileChanges` returns `delete` (recursive) of every start
  path for `-delete`, and for `-exec/-execdir/-ok/-okdir` whose inner command
  is a `FileOperator` with a `{}` operand. That is deliberately
  conservative: `find ~ -name '*.log' -delete` is judged as "may remove
  anything under ~", which is the honest answer at argv time.
- **Unwrap keeps the outer argv**: `unwrapMiddleware` stores the original
  argv in the context (`withOuterArgv`); `fsMiddleware` evaluates
  `FileChanges` of the outer command when it is `find`, and ignores inner
  operands that are the literal `{}`. `sudo rm`, `env rm`, `timeout 5 rm`
  need nothing extra: the inner `rm` is what the guard sees.
- **`rsync --delete` / `--remove-source-files`**: add `delete` (recursive)
  of the destination / sources to `Rsync.FileChanges`.
- **`git clean`, `git checkout`/`reset --hard` in a preexisting checkout**:
  not modelled; covered by reconcile verification only. Listed as a gap.

## Audit integration — `audit.go`

- `AuditRecord.Observed []command.FileChange` — what the reconcile walk saw
  this command actually do (the real file list for `tar -x`, or the writes
  of an in-sandbox binary). `fsMiddleware` runs *inside* audit, so it hands
  results up through a small per-call slot on the context that
  `auditMiddleware` creates and reads after `next` returns.
- `TextAuditor`: an `observed:` line (only entries not already in `files:`),
  and at the end of the run the `- name: files` summary from `Report()`.
- Violations found by reconcile are their own record: `- name: files-verify`
  with `reason: preexisting path removed by unmodelled command: …`.

## CLI — `cmd/smash/main.go`

- `-fs-guard off|warn|deny` (default `deny`).
- `-fs-overwrite` — also protect preexisting files from overwrite.
- `-fs-allow glob,glob` — exemptions.
- `-files FILE|-` — write the end-of-run file report (YAML) separately from
  the audit log.

Library default: `NewConfig` sets `Files.Mode = Deny` (the zero `Config`
stays Off). Expectation: the fixture tests keep passing because every root
is fresh, so everything an installer removes is its own — apart from the
`home`/`tmp` dirs the harness makes, which no installer should delete. Any
test that trips is a real finding about that installer and goes in the
README; `withFileGuard(Warn)` exists as a test option for it.

## Tests — `internal/sandbox/files_test.go`, `fsguard_test.go`

- **`TestFileStateTracksChanges`** — script does `mkdir`, `touch`, `cp`,
  `mv`, `ln -s`, `rm`, `> f`, `>> f`, `tar -xf` (of a tarball built with the
  existing helper); assert the ledger's entries, origins and event chains,
  and that the tar record's `observed:` lists the extracted files.
- **`TestFileGuardBlocksPreexisting`** — pre-seed the root with
  `home/.bashrc` and `home/.config/x/y`, then table-drive:
  `rm ~/.bashrc`, `mv ~/.config/x ~/old`, `rm -rf ~/.config` (descendant
  rule), `mv new ~/.bashrc` (clobber), `sudo rm ~/.bashrc`, `sh -c 'rm
  ~/.bashrc'`, `find ~ -name .bashrc -delete`, `find ~ -name .bashrc -exec rm
  {} \;`, `cd ~/.config && rm x/y` (relative path) — each exits 1 with the
  reason in the audit record and the file still on disk. Allowed: `rm -rf
  ~/.cache/new`, `mkdir ~/.d && rmdir ~/.d`, `>> ~/.bashrc`, `> ~/.bashrc`
  without `Overwrite`.
- **`TestFileGuardOverwrite`** — with `Overwrite`: `> ~/.bashrc`, `cp x
  ~/.bashrc`, `sed -i … ~/.bashrc` denied; `>>` still fine.
- **`TestFileGuardOutsideRoot`** — `rm` of a file in a second `t.TempDir()`
  denied; `touch` then `rm` of a file the script created there allowed.
- **`TestFileGuardWarnMode`**, **`TestFileGuardAllowGlobs`**.
- **`TestFileGuardCatchesUnmodelledRemoval`** — put a script `bin/nuke`
  inside the root (`#!/bin/sh` + `rm "$HOME/.bashrc"`): the escape hatch runs
  it as a real process outside the interpreter, the argv guard cannot see
  the `rm`, reconcile finds `.bashrc` gone, the run ends with
  `*ProtectedRemovedError` and a `files-verify` record. This is the test that
  pins the soft-boundary story honestly.
- **`TestFileChanges`** gains the `find -delete` / `find -exec rm {}` and
  `rsync --delete` cases.
- Full suite under the new `NewConfig` default.

## Known limits (go in the README section)

- Argv-level: a command that takes its paths from stdin (`xargs rm`), an
  unmodelled tool (`perl -e unlink`, `python`), or a binary running from
  inside the root can remove anything. Reconcile turns those into a detected
  and reported violation, not a prevented one. Prevention needs OS
  confinement (the README's Hardening section).
- Outside the root there is no snapshot, so reconcile cannot verify; only
  argv-derived changes are tracked there.
- Hard links and bind mounts are not tracked; a symlink *leaf* is judged as
  the link, not its target.
- `mv` of a preexisting path in Warn mode carries protection to the new
  path, but a later `cp` of that file yields an unprotected copy — by design
  (the copy is the script's).

## Order of work

1. `command`: `Find.FileChanges`, `Rsync` delete flags, outer-argv stash in
   `unwrapMiddleware`; extend `TestFileChanges`.
2. `files.go`: `FileState`, snapshot, resolve, `Protected`, `Apply`,
   `Reconcile`, `Report`, `RunFiles`; `TestFileStateTracksChanges`.
3. `fsguard.go`: `FileGuard`, exec + open middleware, wiring in
   `buildRunner`, `Config.Files`/`State`, `NewConfig` default; guard tests.
4. `audit.go`: `Observed`, the ctx slot, `files-verify` and end-of-run
   summary in `TextAuditor`.
5. CLI flags, README section ("Filesystem state and the removal guard"),
   file-header index in `sandbox.go`.
6. Run the full suite; run rvm/uv fixtures with `-fs-guard deny` and time
   the reconcile walk; pick the `Reconcile` default from the numbers.

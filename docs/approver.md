# External command approval

`-approve prompt` asks on a dedicated `/dev/tty`; `y` allows once, `a` allows
that command name for the session, and every other answer denies. Pipeline
prompts are serialized. Piped script input remains available to the script.

`-approve https://approver.example` uses **Connect RPC**. Smash is the client;
the operator supplies the server. The URL is a base URL, with an optional path
prefix, rather than an individual RPC URL. Both script and interactive runs,
and both block and monitor modes, support approval.

```bash
# Terminal 1: reference supervisor, listening on localhost
 go run ./tools/approver -allow-all -deny rm,curl -log approvals.jsonl
# Terminal 2
 smash -i -approve http://127.0.0.1:8787
```

The reference server denies everything unless `-allow-all` is present; `-deny`
always wins. `-listen` defaults to `127.0.0.1:8787`, and `-log -` logs to stderr.
It is a development harness with no authentication; place an authenticated
service in front of it if exposing it outside the host.

## API and generation

The version 1 contract is [approve.proto](../proto/smash/approve/v1/approve.proto).
Generated public Go packages are in `gen/smash/approve/v1` and
`gen/smash/approve/v1/approvev1connect`. Normal builds use the checked-in Go
files; regeneration needs [Buf](https://buf.build/docs/installation/):

```bash
buf generate
```

`buf.gen.yaml` pins both Go generators. Connect provides protobuf and JSON
encoding, cancellation, HTTP routing, and typed client/server interfaces; see
[Connect for Go](https://connectrpc.com/docs/go/getting-started/).
The client uses the Connect protocol with protobuf encoding. Generated server
handlers also support Connect JSON, gRPC, and gRPC-Web.

All procedures are under `/smash.approve.v1.ApprovalService/`:

| RPC | Request | Response and behavior |
|---|---|---|
| `OpenSession` (unary) | `version=1`, random client `session`, `pid`, `user`, `host`, sandbox `root`, `mode`, `interactive` | Requires `version=1`; `audit=true` requests audit streaming; positive `timeout_ms` overrides the client's per-decision timeout; zero keeps it; negative is invalid |
| `Approve` (unary) | `session`, monotonic string `id`, shell `dir`, redacted `command` | Required optional-bool `allow`, optional `reason`, and `remember` enum (`REMEMBER_UNSPECIFIED`, `REMEMBER_ARGV`, `REMEMBER_NAME`) |
| `Audit` (client stream) | Every item contains `session` and an audit `record` | Server consumes records as they arrive, returns a record count on stream close |

OpenSession completes before commands run. Decisions have independent RPCs, so
concurrent pipeline stages may receive responses in any order. Session IDs
associate requests and records; they are **not authentication credentials**.


A command carries `name`, normalized/redacted `argv` and `line`, peeled
`wrappers`, `resources` (`kind`, `action`, `value`), optional `egress` (`target`,
`kind`: 0 indicator, 1 endpoint, 2 URL), `files` (`op`, `path`, `from`,
`recursive`), and the local gate `verdict`. Verdicts are `allowed`, `unlisted`,
`sensitive-blocked`, `strict-blocked`, `disabled-blocked`, `in-root-script`,
`in-root-interpreter`, or `in-root-native`. These describe the final host gate:
commands served before that gate, such as confined `sh -c` or in-process
`curl`, can still require approval despite a blocked host-gate verdict.

Audit records explicitly convert `Params` to a string, errors to `exit` and
`error`, and duration to `duration_ms`. Other fields include resources, egress,
files, reason, serving layer, content type, sniffed content type, redirect hops,
wrappers, and unlisted/in-root flags. Shell opens are records named `shell`;
they are observed, not approval-gated. Binary stream captures are not sent.
Audit calls do not wait for network writes: a 256-record queue feeds the
stream. Overflow or a stream failure disconnects the approver rather than
silently dropping evidence. Shutdown allows one second to flush and acknowledge
remaining records before cancelling the stream.

## Enforcement and failures

Approval only narrows permission. In block mode, disabled commands, mocks,
sudo probes, and commands already blocked by the local gate are not submitted.
The audit stream can still show their outcomes. Network policy is checked after
approval: an allow cannot grant an off-policy URL. In monitor mode every command
that reaches the approval layer is submitted, with the gate's hypothetical
verdict. Shell builtins, assignments, and redirections do not go through the
external command approval layer.

`sh -c` requires approval for the shell invocation and each inner external
command. Find/xargs iteration drivers are skipped, but their children require
approval. Remembered grants and denials last for the session and are shared
with confined sub-runners. `ARGV` uses the original exact argv as its cache key,
so normalization or credential redaction cannot merge different invocations.
It does not include cwd; `NAME` covers all invocations with that command name.

`-approve-timeout` defaults to `60s` and bounds startup and each decision.
A shorter statement deadline still wins. Denial, cancellation, an absent
`allow`, an invalid remember enum, or an RPC error fails closed with status 126
and `served: approve` in the audit. A failed OpenSession is a startup error.
Transport/protocol failures invalidate the session, cancel pending requests,
and produce one disconnection notice. Later requests fail without reconnecting.
A single request's deadline or cancellation does not invalidate the session.
Server reason strings have control characters escaped before terminal display.

HTTPS uses the system certificate pool. There is no insecure TLS flag. Policy
headers are literal, with no environment interpolation. `SMASH_APPROVE_TOKEN`
adds `Authorization: Bearer …` unless a case-insensitive Authorization header
is already configured. Headers are sent on every RPC, including the audit
stream. Redirects are refused. No credential flag appears in process arguments.

```yaml
mode: block
approve:
  url: https://approver.example
  timeout: 60s
  headers:
    X-Team: release
```

## Implementing a supervisor

Implement the generated `ApprovalServiceHandler`, then mount it on a normal
HTTP server. The complete, runnable implementation is
[tools/approver/main.go](../tools/approver/main.go). An Approve method can be as
small as:

```go
func (s *Server) Approve(ctx context.Context, req *connect.Request[v1.ApproveRequest]) (*connect.Response[v1.ApproveResponse], error) {
    allow := req.Msg.Command.Name != "rm"
    return connect.NewResponse(&v1.ApproveResponse{
        Allow: &allow,
        Reason: "operator rule",
        Remember: v1.Remember_REMEMBER_UNSPECIFIED,
    }), nil
}
```

The server also implements OpenSession and Audit as shown in the reference
server. Other languages can generate clients and handlers from the same proto.
Reconnect, pushed rules, persisted decisions, and gating shell opens are not
implemented in this version.

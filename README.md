# burp-mcp-ultimate

Burp Suite Pro extension that exposes the entire Montoya API as an MCP (Model Context Protocol) server, so any MCP-aware AI agent (Claude Code, Claude Desktop, Cursor, BountyHound, ...) can drive Burp programmatically with **functional 100% coverage**.

[![build](https://github.com/your-org/burp-mcp-ultimate/actions/workflows/build.yml/badge.svg)](https://github.com/your-org/burp-mcp-ultimate/actions/workflows/build.yml)

## At a glance

- **129 first-class MCP tools** across 30 surfaces
- **10 MCP Resources** + **9 MCP Prompts** + **resources/subscribe** for live change notifications
- **SSE push** of every event-bus event, tool call, and progress notification
- **Hold-and-decide intercept queue** lets the agent modify proxy traffic mid-flight
- **Editor read/write** via right-click capture
- **Reflection escape hatch** covers anything we did not first-class wrap
- **Per-session log + rate limiter**, configurable CORS allow-list, query-string token fallback, structured error codes
- **Unit-tested foundation** (HandleStore, Reflect overload picker, EventBus, InterceptQueue) - all passing

## Architecture

Every Montoya method is reachable through one of these layers:

1. **First-class tools** (129 named, schema-typed) - the common operations.
2. **Composite tools** (~5) - JSON-spec wrappers around the dozens of `with*` builder methods on each data type.
3. **Reflection escape hatch** (`montoya_invoke`, `montoya_invoke_static`, `montoya_inspect`, `montoya_list_methods*`) - dispatch any Java method by name. Score-based overload picking (exact-class > assignable > primitive boxing).
4. **Callback bridge / event bus** - converts Burp's handler-style APIs into a poll-based event stream the agent can subscribe to (also pushed live over SSE).
5. **Hold-and-decide intercept queue** - `intercept_set_mode hold_both` pauses the proxy thread; agent decides via `intercept_resolve` with optional modified bytes, with a 30 s timeout fail-open.
6. **Editor capture via right-click** - context-menu integration captures the active Burp message editor; agent reads/modifies what the user is staring at. Capture goes stale after 10 minutes (configurable).
7. **MCP Resources** - read-only data the model auto-pulls into context. Supports subscribe/unsubscribe with change notifications.
8. **MCP Prompts** - canned hunting workflows.
9. **SSE push** - server-initiated MCP notifications stream every event-bus event, tool-call summary, and progress update to connected clients live.

Returned objects that are non-primitive get stored in a **handle store**; the agent passes `{"$handle": "h12"}` to chain operations across tool calls.

## Tool inventory (highlights)

| Surface | Tools |
|---|---|
| HTTP | `http_send_raw`, `http_send_with_session_handling`, `http_send_batch`, `http_send_race`, `http_url_to_request`, `cookie_jar_list`, `cookie_jar_set` |
| GraphQL | `graphql_introspect`, `graphql_query`, `graphql_batched_query`, `graphql_field_suggestions` |
| OAuth/OIDC | `oidc_discover`, `oauth_decode_access_token`, `oauth_build_pkce`, `oauth_token_exchange` |
| JWT | `util_jwt_decode`, `jwt_verify`, `jwt_sign`, `jwt_alg_confusion`, `jwt_kid_inject`, `jwt_jwks_fetch` |
| Diff | `diff_text`, `diff_responses` |
| JS analysis | `js_extract_endpoints`, `js_scan_secrets`, `js_scan_response` |
| Editor | `editor_describe`, `editor_get_request`, `editor_get_response`, `editor_set_request`, `editor_set_response`, `editor_clear_capture` |
| Intercept | `intercept_set_mode`, `intercept_status`, `intercept_pending_list`, `intercept_get_full`, `intercept_resolve` |
| Annotations | `annotation_set`, `annotation_get` |
| Events | `events_subscribe`, `events_poll`, `events_unsubscribe`, `events_list_channels`, `events_list_subscriptions` |
| Persistence | `notes_*`, `persist_set/get_int/bool/request/response/request_response`, `persist_keys`, `persist_delete` |
| Reflection | `montoya_invoke`, `montoya_invoke_static`, `montoya_inspect`, `montoya_list_methods`, `montoya_list_methods_of_class` |
| Plus | Proxy, Repeater, Intruder (incl. `intruder_send_template` with positions), Scanner, Collaborator, Sitemap, Scope, WebSockets (read+write), Organizer, Comparer, Decoder, Logger, Util/UtilExt, BurpSuite |

(Full alphabetical list at `/mcp -> tools/list`.)

## MCP Resources (10)

| URI | Content |
|---|---|
| `burp://proxy/history` | Last 200 proxy items |
| `burp://sitemap` | First 500 sitemap nodes |
| `burp://scan/issues` | All scanner issues |
| `burp://issues/critical` | High + Critical only |
| `burp://websockets/active` | WS frame counts per upgrade URL |
| `burp://target_summary` | Top hosts by request count |
| `burp://collaborator/server` | Collaborator hostname info |
| `burp://scope` | Scope-enumeration limit note |
| `burp://handles` | Currently stored handles |
| `burp://intercept/pending` | Pending intercept queue |

Subscribe via `resources/subscribe { uri }` to get live notifications when content changes.

## MCP Prompts (9)

`audit_auth_flow`, `find_idor_pairs`, `find_ssrf`, `analyze_jwt`, `audit_oauth_flow`, `find_race_conditions`, `audit_file_upload`, `analyze_graphql_schema`, `analyze_response`

## Build

Requires JDK 21. Gradle wrapper is committed.

```powershell
./gradlew test           # 18 unit tests
./gradlew shadowJar      # build/libs/burp-mcp-ultimate-0.2.0.jar
# Override Montoya version:
./gradlew shadowJar -PmontoyaVersion=2024.12
```

## Load into Burp Suite Pro

1. Burp -> **Extensions** -> **Add**.
2. Type: **Java**.
3. File: `build/libs/burp-mcp-ultimate-0.2.0.jar`.
4. MCP server starts on `http://127.0.0.1:9444/mcp`.
5. **MCP** tab in Burp shows endpoint, sessions, tool calls, handles, SSE clients, intercept mode/pending, event channels.

## Configuration (env vars or system properties)

| Var | Default | Purpose |
|---|---|---|
| `BURP_MCP_HOST` | `127.0.0.1` | Bind address |
| `BURP_MCP_PORT` | `9444` | Port |
| `BURP_MCP_TOKEN` | (none) | Bearer token (also accepted as `?token=...` query) |
| `BURP_MCP_CORS_ORIGINS` | `*` | Comma-separated allow-list, or `*` |
| `BURP_MCP_RATE_LIMIT` | `0` (off) | Max tool calls per session per 10 s |
| `BURP_MCP_EDITOR_STALE_SECONDS` | `600` | Editor capture is rejected after this age |

```powershell
$env:BURP_MCP_TOKEN = "your-long-random-token"
$env:BURP_MCP_CORS_ORIGINS = "http://localhost:3000,https://localhost:9777"
$env:BURP_MCP_RATE_LIMIT = "120"
& "C:\Program Files\BurpSuitePro\BurpSuitePro.exe"
```

## Wire into Claude Code

```jsonc
// ~/.claude.json
{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url":  "http://127.0.0.1:9444/mcp?token=your-long-random-token"
    }
  }
}
```

> **Use `"type": "http"`, not `"type": "sse"`.** This server speaks the MCP Streamable HTTP transport (POST = JSON-RPC request/response, optional GET = SSE for server-initiated notifications, same URL). The `"type": "sse"` value selects the legacy MCP-over-SSE transport that expects the server to emit an `event: endpoint` frame first, which this server does not. Using `"sse"` will hang at "connecting…" with no error.

## Right-click integration

Three menu items added to Burp's right-click everywhere:
- **AI: capture this editor** in any message editor - stash the editor reference; `editor_get_request/set_request` work against it.
- **AI: send N item(s)** in proxy / sitemap / etc. - store selected requests as handles, push a `context_menu` event.
- **AI: send N issue(s)** in scan issues - same for scan issues.

## Sessions

Per-client session id from header `Mcp-Session-Id`, minted automatically if absent. Each session has its own tool log + rate-limit bucket. Sessions list visible in the MCP tab.

## Structured error codes

Beyond JSON-RPC standard codes:

| Code | Meaning |
|---|---|
| -32001 | UNAUTHORIZED |
| -32002 | NOT_FOUND (handle / resource / prompt / tool) |
| -32003 | VALIDATION (arg fails business validation) |
| -32004 | TARGET_ERROR (remote target failed) |
| -32005 | RATE_LIMITED |
| -32006 | STALE (editor capture / handle past TTL) |
| -32007 | MONTOYA_ERROR (Burp threw) |

## Smoke tests

```powershell
# initialize
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}'

# resources + prompts
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":2,"method":"resources/list"}'
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":3,"method":"prompts/list"}'

# enable intercept
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"intercept_set_mode","arguments":{"mode":"hold_requests"}}}'

# subscribe to scan_issue events
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"events_subscribe","arguments":{"channel":"scan_issue"}}}'

# reach a method we did not wrap (Proxy.isInterceptEnabled)
curl -s -X POST http://127.0.0.1:9444/mcp -H "Content-Type: application/json" `
  -d '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"montoya_invoke","arguments":{"target":"api","method":"proxy"}}}'
```

## Security notes

- Default bind is `127.0.0.1`. Do not expose to the network.
- If you must, set a token AND lock CORS to specific origins AND put TLS on a reverse proxy.
- The agent operates with full Burp privileges. Treat any AI client connected to it as if it were you, sitting at the keyboard.

## Real Montoya gaps (not bugs - the API doesn't expose these)

- Scope rule enumeration (`scope_is_in_scope` works, listing rules does not)
- BCheck listing / enable / disable (import only)
- Intruder attack-result table readback (launch only)
- Scanner pause/resume per task (delete + status only)
- Burp AI assistant API
- BApp Store enumeration / install
- Bambdas (Burp's filter DSL) execution
- Cookie attributes beyond name/value/domain/path

These are reachable from the reflection escape hatch the moment PortSwigger ships the corresponding Montoya methods.

## Acknowledgements

Patterns and naming influenced by reading the public docs of:
- [PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server) - Apache 2.0
- [six2dez/burp-ai-agent](https://github.com/six2dez/burp-ai-agent) - MIT
- [swgee/BurpMCP](https://github.com/swgee/BurpMCP) - MIT

## License

MIT

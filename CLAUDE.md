# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Kotlin/JVM Burp Suite Pro extension (Montoya API) that runs an in-process MCP (Model Context Protocol) server on `http://127.0.0.1:9444/mcp`. It exposes ~129 first-class MCP tools + 10 resources + 9 prompts so any MCP client (Claude Code, Claude Desktop, Cursor, BountyHound) can drive Burp programmatically. Loaded into Burp via `Extensions -> Add -> Java`.

## Build / test / run

JDK 21 required. Gradle wrapper is committed.

```powershell
./gradlew test                           # JUnit 5, currently 4 test classes (HandleStore, Reflect, EventBus, InterceptQueue)
./gradlew test --tests "ReflectTest"     # single test class
./gradlew test --tests "*pickOverload*"  # single test method
./gradlew shadowJar                      # build/libs/burp-mcp-ultimate-0.2.0.jar (the loadable extension)
./gradlew shadowJar -PmontoyaVersion=2024.12   # override Montoya version
```

There is no `lint` / `format` task wired in; `kotlin.code.style=official` is set in `gradle.properties`.

To exercise the running server end-to-end you must load the shadow JAR into a real Burp Suite Pro instance — there is no headless harness for the Montoya API. Smoke-test endpoints are documented in `README.md` (initialize / resources/list / tools/call). The `/healthz` endpoint returns `ok`.

## Architecture (the part you can't see by listing files)

Single `BurpExtension` entrypoint at `BurpMcpUltimateExtension.initialize()` wires every collaborator and starts an embedded `MicroHttpServer` (`mcp/MicroHttp.kt`). **There is no DI framework — read that one method to see how everything connects.**

> **Why a custom HTTP server?** Burp Suite (Pro and Community) ships a jlink'd JRE that excludes `jdk.httpserver`. `com.sun.net.httpserver.HttpServer` throws `ClassNotFoundException` at extension load. `MicroHttp.kt` is a ~250-line HTTP/1.1 server using only `java.net.ServerSocket` + `java.base`. Its `HttpExchange` API mirrors `com.sun.net.httpserver.HttpExchange` exactly so `McpServer.kt` and `SseHub.kt` use it transparently. Do NOT swap back to `com.sun.net.httpserver` — it will break Burp loading. Streaming semantics: `sendResponseHeaders(code, 0)` -> `Transfer-Encoding: chunked` (for SSE), except 1xx/204/304 which get neither length nor encoding header per RFC 7230. The handler is responsible for closing `responseBody` for non-streaming responses; SSE handlers leave it open and `SseHub` owns the lifecycle.

Three-layer Montoya coverage strategy:
1. **First-class tools** (named, JSON-Schema-typed) under `tools/*Tools.kt`, each with a `register(reg, api, ...)` static entrypoint. All are aggregated by `tools/Tools.kt :: registerAllTools()`.
2. **Composite tools** (`CompositeTools.kt`) — JSON-spec wrappers for Montoya's many `with*` builder methods.
3. **Reflection escape hatch** (`ReflectTools.kt` + `mcp/Reflect.kt`) — `montoya_invoke` / `montoya_invoke_static` / `montoya_inspect` dispatch any Java method by name with score-based overload picking (exact-class > assignable > primitive boxing). Registered last so richer first-class schemas show first in tool listings.

Fourth layer (added later): **`bridge/ExtensionBridge.kt`** — cross-extension reflection bridge that walks running threads to discover *other* Burp extensions' ClassLoaders, then does classloader-aware reflection against them. Used by `BridgeTools.kt` (8 generic tools) + `ExtensionWrappers.kt` (typed wrappers for Logger++, Hackvertor, Param Miner, Turbo Intruder). See `docs/EXTENSION_BRIDGE.md` for the rationale, status table, and caveats. **Do not rely on third-party extensions' class names being stable** — KNOWN_EXTENSION_CLASSES is verified against publicly-released source as of build, but BApp Store updates can shift them.

Cross-cutting collaborators (in `mcp/`):
- **`HandleStore`** — opaque `h<n>` IDs for non-primitive Java objects (1h TTL, 5000 cap, time-based eviction). The agent passes `{"$handle": "h12"}` to chain Montoya calls across requests. **This is the central abstraction; nearly every tool either consumes or produces a handle.**
- **`EventBus`** — converts Burp's handler-style APIs (HttpHandler, ProxyRequestHandler, ScanCheck, etc.) into a poll-based stream (`events_poll`) AND pushes via `SseHub` for live MCP notifications.
- **`InterceptQueue`** — hold-and-decide proxy interception. `intercept_set_mode hold_both` pauses the proxy thread; agent calls `intercept_resolve` with optional modified bytes; **30s timeout fail-open** (the proxy must not deadlock).
- **`EditorRegistry`** — captures the active Burp message editor via right-click (`ContextMenuTools`); `editor_get_request/set_request` operate against it. Capture goes stale after `BURP_MCP_EDITOR_STALE_SECONDS` (default 600).
- **`SessionRegistry`** — per-`Mcp-Session-Id` tool log + token-bucket rate limiter (`BURP_MCP_RATE_LIMIT` calls per 10s, 0=off).
- **`ResourceRegistry` + `SseHub`** — MCP resources support `resources/subscribe`; SseHub fans out change notifications.
- **`Progress`** — wraps long-running tools (`BulkTools`) with progress notifications over SSE.

Tool handler contract (`ToolRegistry.call`): handler returns `String` -> wrapped as single `TextContent`; `ToolCallResult` -> passed through; anything else -> Jackson-serialized. Handlers throw `McpException(code, message)` for structured JSON-RPC errors using app-specific codes in `ErrorCodes` (-32001..-32007). Other throwables are caught and wrapped as `isError=true` content, **not** as JSON-RPC errors — the protocol distinction matters.

## Critical conventions when editing

- **Adding a new tool**: create or extend a `tools/XxxTools.kt` with `object XxxTools { fun register(reg: ToolRegistry, api: MontoyaApi, ...) }`, then add the call inside `tools/Tools.kt :: registerAllTools()` in the right phase (first-class before composite before reflection). Use `ToolRegistry.Schema` builders for `inputSchema` and `Args.str/int/bool/list` for arg coercion.
- **Returning a Montoya object**: store via `handles.put(obj)` and return the handle id, never the raw object. Returning a raw Java object will break Jackson serialization for many Montoya types.
- **Long-running operations**: emit progress via `Progress` (see `BulkTools`), don't block the HTTP thread for >a few seconds — the executor pool is fixed at 8.
- **Intercept handler**: never block indefinitely. The 30s fail-open in `InterceptQueue` is load-bearing; do not remove it without a replacement deadlock guard.
- **Shadow JAR relocations** in `build.gradle.kts` (`com.fasterxml.jackson` -> `io.burpmcp.shaded.jackson`, `kotlinx.coroutines` -> `io.burpmcp.shaded.coroutines`) are required because Burp loads extensions in a shared classloader and unrelocated deps collide with other extensions. Do not import shaded packages directly in source — import the original package; the relocator rewrites bytecode.
- **`tasks.jar { enabled = false }`** — only the shadow JAR is shippable. `./gradlew build` triggers `shadowJar` via `tasks.build { dependsOn(tasks.shadowJar) }`.
- **Montoya version** is a Gradle property (`montoyaVersion` in `gradle.properties`, default 2024.12) — override per-build with `-PmontoyaVersion=...`. The Montoya jar is `compileOnly` because Burp provides it at runtime; don't switch it to `implementation` (would bloat the shadow JAR and risk classloader conflicts).

## Configuration (env vars / system properties — read in `mcp/Config.kt`)

`BURP_MCP_HOST` (127.0.0.1), `BURP_MCP_PORT` (9444), `BURP_MCP_TOKEN` (off; also accepted as `?token=...`), `BURP_MCP_CORS_ORIGINS` (`*`, comma-separated), `BURP_MCP_RATE_LIMIT` (0=off), `BURP_MCP_EDITOR_STALE_SECONDS` (600). System properties take precedence over env vars.

## Real Montoya gaps (won't fix in this repo — upstream API doesn't expose them)

Scope rule enumeration, BCheck listing/enable/disable, Intruder attack-result table readback, Scanner per-task pause/resume, Burp AI assistant API, BApp Store enumeration, Bambdas execution, full Cookie attributes. All become reachable through `montoya_invoke` once PortSwigger ships them.

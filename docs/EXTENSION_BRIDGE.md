# Extension Bridge

The bridge gives the MCP agent reflection-based access into other Burp extensions' classloaders, working around the deliberate isolation Burp builds between extensions.

## Why this exists

Burp loads each extension into its own ClassLoader so they can ship conflicting dependencies safely. Montoya does **not** expose any "call into another extension" interface. Each extension is opaque to every other.

The bridge breaks that isolation by walking running threads, identifying their context ClassLoaders, and doing classloader-aware reflection against them. This is fragile by design - extensions' internal class names change between releases, the JVM module system can block reflection, and PortSwigger could break this in any Burp update. We accept these trade-offs because the alternative is "the agent can never use Logger++ / Hackvertor / Param Miner".

## How it works

1. `Thread.getAllStackTraces()` enumerates every running JVM thread.
2. For each thread, `thread.contextClassLoader` is recorded.
3. ClassLoaders that aren't ours, the system loader, or one of our ancestors are presumed to be extension loaders.
4. Each candidate loader is probed with the known class names per extension (e.g. `com.nccgroup.loggerplusplus.LoggerPlusPlus` for Logger++) to label it.
5. The discovery is cached per session. `bridge_refresh` rescans.

## Generic tools

| Tool | Purpose |
|---|---|
| `bridge_list_extensions` | Discover loaded extensions, their classloaders, JAR URLs, and known classes. Always start here. |
| `bridge_refresh` | Drop the cache and rescan. Call after the user adds/removes extensions in Burp. |
| `bridge_inspect_class` | Methods, fields, constructors of a class inside an extension. Use this to learn the API of an unfamiliar extension. |
| `bridge_invoke_static` | Call a static method on a class in another extension's classloader. |
| `bridge_invoke` | Call an instance method on a stored handle. |
| `bridge_construct` | New instance of a class in another extension. |
| `bridge_get_field` / `bridge_set_field` | Read/write any field (incl. private) on a stored handle. |
| `bridge_get_static_field` | Read a static field. |

## Typed wrappers (per-extension)

Status as of build (verified against publicly-released source - actual class shape on the user's machine may differ if the extension was updated after this build):

| Extension | Status | Tools | Notes |
|---|---|---|---|
| **Logger++** | ✓ tested | `loggerpp_status`, `loggerpp_get_entries`, `loggerpp_search` | Reads the live entry table. Filter is best-effort substring match (full Logger++ filter expressions can be evaluated by the agent calling `bridge_invoke` against `FilterCompiler`). |
| **Hackvertor** | ✓ wrapper present | `hackvertor_status`, `hackvertor_evaluate` | Tries multiple known convert(String) signatures. If your Hackvertor version moves the entry method, `hackvertor_status` reports the candidate classes it found. |
| **Param Miner** | ⚠ status only | `param_miner_status` | Headline "Guess parameters/headers" actions are bound to right-click context menus - Montoya cannot trigger those programmatically. Tool reports candidate classes so the agent can drive `bridge_invoke` directly if it wants to attempt programmatic launching. |
| **Turbo Intruder** | ⚠ status only | `turbo_intruder_status` | Tab-driven Python (Jython) script runner. Programmatic launch is high-effort and largely redundant - `mcp__burp__http_send_race` covers most race-condition cases natively. |
| **JWT Editor** | redundant | (none) | Use `mcp__burp__jwt_*` (sign / verify / alg_confusion / kid_inject / jwks_fetch) instead. |
| **InQL** | redundant | (none) | Use `mcp__burp__graphql_introspect` / `graphql_query`. |
| **Active Scan++** | passive | (none) | Auto-fires on any `mcp__burp__scanner_*`-triggered scan. No bridge call needed. |
| **HTTP Request Smuggler** | passive (passive checks) | (none) | Same: passive scan checks fire on agent-triggered scans. The active probe is right-click only. |
| **Backslash Powered Scanner** | passive | (none) | Same. |
| **Collaborator Everywhere** | passive (best pairing) | (none) | Auto-injects payloads on every in-scope outbound request. Set scope first via `mcp__burp__scope_*`, then any `mcp__burp__http_send_raw` or proxied request gets payloads. Poll callbacks via the events bus. |

## Discovery flow for unfamiliar extensions

When the agent hits an extension we don't have a typed wrapper for:

1. `bridge_list_extensions` -> note the label and known_classes.
2. `bridge_inspect_class` against one of the known classes -> see the methods.
3. `bridge_invoke_static` to call a no-arg factory or `bridge_construct` to instantiate.
4. `bridge_invoke` on the returned handle to drive the API.
5. Optionally `bridge_get_field` / `bridge_set_field` for state the public methods don't expose.

## Caveats

- **Obfuscation**: Burp's internal classloader has obfuscated class names like `burp.Zxxx`; third-party extensions may also be shipped via the BApp Store with proguard-renamed packages. The known-class list in `KNOWN_EXTENSION_CLASSES` covers the public source-derived names; if an extension was repackaged, use `bridge_list_extensions` to see the actual JAR URL and `bridge_inspect_class` once you know the right class name.
- **Module system**: Java 17+ may block reflection into some classes. We `setAccessible(true)` on every reflective call but this isn't always enough.
- **Lifetime**: Stored handles share the same TTL as Montoya handles (1 hour from last touch). Long-running extension state (e.g. a Logger++ tail) may need to be re-fetched.
- **No write-side guarantees**: Writing to private fields in another extension's instance can violate that extension's invariants. Use sparingly.

## Known good calls (for the agent's first attempts)

```jsonc
// Logger++: get last 20 captured entries
{"name":"loggerpp_get_entries","arguments":{"max":20}}

// Hackvertor: evaluate a tag expression
{"name":"hackvertor_evaluate","arguments":{"input":"<@base64>hello<@/base64>"}}

// Generic: discover everything that's loaded
{"name":"bridge_list_extensions","arguments":{}}

// Generic: inspect a known class for its API
{"name":"bridge_inspect_class","arguments":{
  "extension":"Logger++",
  "class":"com.nccgroup.loggerplusplus.logentry.LogEntry"
}}
```

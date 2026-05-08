# Morning Report — overnight audit + bridge build

Status as of last commit: **62 tests passing, 151 tools, clean tree, all on `main`**.

## Commit timeline (newest -> oldest)

| Commit | What |
|---|---|
| `[next]`  | Polish: dedupe `DEFAULT_PARAM_WORDLIST`, write this morning report |
| `3838375` | Add `fingerprint_target` + `open_redirect_probe` |
| `081f8c9` | Add agent-native attack tools (`param_miner_lite`, `bypass_403`, `cors_misconfig_probe`) |
| `fb8f296` | Untrack `.claude/` (Claude Code session state) |
| `356f452` | Add cross-extension reflection bridge |
| `ca626ba` | Initial import: burp-mcp-ultimate v0.2.0 |

## What was built

### 1. Cross-extension reflection bridge (the thing you asked for at bedtime)

Walks running thread classloaders to discover other Burp extensions and reflects into them, working around Montoya's deliberate extension isolation.

**Generic tools (9):**
- `bridge_list_extensions` — enumerate everything loaded
- `bridge_refresh` — drop the discovery cache and rescan
- `bridge_inspect_class` — methods/fields/constructors of any class in any extension
- `bridge_invoke_static` — call a static method
- `bridge_invoke` — call an instance method on a stored handle
- `bridge_construct` — new instance
- `bridge_get_field` / `bridge_set_field` — read/write any field (incl. private, via `setAccessible`)
- `bridge_get_static_field` — read static field

**Per-extension typed wrappers (7):**
- Logger++: `loggerpp_status`, `loggerpp_get_entries`, `loggerpp_search`
- Hackvertor: `hackvertor_status`, `hackvertor_evaluate`
- Param Miner: `param_miner_status` (right-click actions are unreachable from Montoya — agent-native `param_miner_lite` covers the common cases)
- Turbo Intruder: `turbo_intruder_status` (`http_send_race` covers most race-condition cases)

Source: `src/main/kotlin/io/burpmcp/ultimate/bridge/ExtensionBridge.kt` + `tools/BridgeTools.kt` + `tools/ExtensionWrappers.kt`. 13 unit tests.

### 2. Agent-native attack tools (no third-party extension dependency)

These work on a fresh Burp Pro install with zero extensions loaded. They duplicate the most common manual workflows from Param Miner / 403-bypass scripts / CORS test pages so the AI agent doesn't need extension installation to function.

| Tool | What it does |
|---|---|
| `param_miner_lite` | Bulk-probe headers or parameters with a 100+ default wordlist. Compares each response to a baseline, flags status/length/header anomalies and marker reflection. |
| `bypass_403` | 30+ documented 403/401 bypass tricks: path encoding (%2e %2f ..;/ etc.), header tricks (`X-Original-URL`, `X-Custom-IP-Authorization`, `X-Forwarded-For: 127.0.0.1`), method overrides, capitalization. Reports every variant whose status differs from the baseline. |
| `cors_misconfig_probe` | 8 attacker-origin variants (canonical, null, subdomain trick, userinfo trick, etc.). Severity-graded: **critical** if reflection + `Allow-Credentials: true`, **noteworthy** if `*` + credentials, **info** otherwise. |
| `fingerprint_target` | First-look recon in one call: tech-stack from headers, robots.txt, sitemap.xml, security.txt, openid-configuration, common admin paths, baseline-404 calibration, WAF/CDN markers, missing-security-header detection. Replaces ~10 manual `http_send_raw` calls. |
| `open_redirect_probe` | 13 redirect-bypass payloads against a URL parameter. Reports exploitable variants (Location -> attacker host) vs partial (redirects but Location may be sanitized). |

Source: `src/main/kotlin/io/burpmcp/ultimate/tools/AttackTools.kt`. 9 unit tests for the anomaly analyzer covering the threshold edges.

## What you need to do

1. **Reload the extension in Burp**: Extensions -> burp-mcp-ultimate -> uncheck Loaded -> recheck. The new JAR has all 21 new tools.
2. **Run the bridge smoke prompt** in `docs/BRIDGE_SMOKE_PROMPT.md` against your MCP-connected Claude. Paste the resulting matrix back to me. ✓ rows mean it works; ⚠ rows mean a third-party extension's class structure has shifted from what was published in source — typically a one-line fix in `ExtensionBridge.KNOWN_EXTENSION_CLASSES` or `ExtensionWrappers.kt`'s candidate-classes lists.
3. **Try the agent-native tools** with prompts like:
   - "Use mcp__burp__fingerprint_target on example.com" — confirms the recon pipeline works
   - "Use mcp__burp__cors_misconfig_probe on example.com /api" — confirms the CORS detection
   - "Use mcp__burp__bypass_403 on example.com /admin" — confirms the bypass probe works (will obviously not find any bypasses on example.com but exercises the variants)

## Caveats (already in `docs/EXTENSION_BRIDGE.md`)

- **Bridge is fragile by design.** Third-party extensions' internal class names change between releases. Generic `bridge_invoke` is the durable fallback — even if a typed wrapper breaks, the agent can still drive any extension via raw reflection.
- **Param Miner's headline actions are right-click only.** Montoya can't trigger context menus. The agent-native `param_miner_lite` is designed to cover that gap.
- **Turbo Intruder programmatic launch is high-effort and largely redundant** — `http_send_race` covers most race-condition use cases natively.
- **Anomaly thresholds in `param_miner_lite`** flag changes >= 50 bytes OR >= 5% body delta, plus status changes, marker reflection, new headers. Tested against the empty-body edge case (was a bug in the first version, fixed in `081f8c9`).

## Test count progression

| Stage | Tests |
|---|---|
| At start of overnight session | 40 |
| After bridge core | 53 |
| After AttackTools | 62 |

## Known follow-ups (not done overnight, by your discretion)

- **Logger++ filter expression evaluation** — currently the `loggerpp_search` wrapper does substring matching across all visible fields. The full Logger++ filter DSL (e.g. `Response.Body CONTAINS "x"`) requires loading their `FilterCompiler` class and evaluating against the entry. The agent can do this today via `bridge_invoke` against `com.nccgroup.loggerplusplus.filter.parser.FilterCompiler`; we could pre-wrap that as a one-liner if you want it baked in.
- **Hackvertor extended** — current wrapper only does `convert(String)`. Hackvertor also has signed tags, custom-tag definitions, and tag scoping. Worth exploring if you find yourself reaching for those.
- **More attack tools** worth considering: `idor_compare(handle_a, handle_b)` (compare same request as two users), `ssti_probe` (server-side template injection), `subdomain_takeover_probe` (CNAME-pointing-to-deleted-resource detection).

The repo is in a fully shippable state. Nothing in flight.

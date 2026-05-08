package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object ProxyTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "proxy_history",
            description = "Get the Burp proxy HTTP history. Optional URL substring filter and pagination.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url_contains" to S.str("Substring filter for the URL"),
                    "method"       to S.str("HTTP method filter (e.g. POST)"),
                    "in_scope"     to S.bool("Only include in-scope items", default = false),
                    "offset"       to S.int("Skip first N items", default = 0),
                    "limit"        to S.int("Max items to return", default = 100),
                ),
            ),
        ) { args ->
            val urlContains = Args.strOrNull(args, "url_contains")
            val method      = Args.strOrNull(args, "method")?.uppercase()
            val inScope     = Args.bool(args, "in_scope", false)
            val offset      = Args.int(args, "offset", 0)
            val limit       = Args.int(args, "limit", 100)

            val history = api.proxy().history()
            val filtered = history.asSequence()
                .filter { item ->
                    (urlContains == null || item.url().contains(urlContains)) &&
                    (method == null || item.method().equals(method, ignoreCase = true)) &&
                    (!inScope || api.scope().isInScope(item.url()))
                }
                .drop(offset).take(limit).toList()

            mapOf(
                "total_in_history" to history.size,
                "returned"         to filtered.size,
                "items"            to filtered.map { item ->
                    mapOf(
                        "method"      to item.method(),
                        "url"         to item.url(),
                        "status_code" to (if (item.hasResponse()) item.response().statusCode().toInt() else -1),
                        "request_len" to item.finalRequest().toByteArray().length(),
                        "response_len" to (if (item.hasResponse()) item.response().body().length() else 0),
                    )
                },
            )
        }

        reg.register(
            name = "proxy_history_regex",
            description = "Filter proxy history with a regex against the URL or full request text.",
            inputSchema = S.obj(
                properties = mapOf(
                    "pattern" to S.str("Java regex"),
                    "field"   to S.enum("Field to match", listOf("url", "request"), default = "url"),
                    "limit"   to S.int("Max items", default = 100),
                ),
                required = listOf("pattern"),
            ),
        ) { args ->
            val pattern = Regex(Args.str(args, "pattern"))
            val field   = Args.strOrNull(args, "field") ?: "url"
            val limit   = Args.int(args, "limit", 100)

            val matches = api.proxy().history().asSequence()
                .filter { item ->
                    val target = if (field == "request") item.finalRequest().toString() else item.url()
                    pattern.containsMatchIn(target)
                }
                .take(limit).toList()

            mapOf(
                "matched" to matches.size,
                "items"   to matches.map { mapOf("method" to it.method(), "url" to it.url()) },
            )
        }

        reg.register(
            name = "proxy_websocket_history_summary",
            description = "Summarise the proxy WebSocket history grouped by URL.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url_contains" to S.str("Substring filter on upgrade URL"),
                ),
            ),
        ) { args ->
            val urlContains = Args.strOrNull(args, "url_contains")
            val msgs = api.proxy().webSocketHistory()
                .filter { urlContains == null || it.upgradeRequest().url().contains(urlContains) }
            val byUrl = msgs.groupBy { it.upgradeRequest().url() }
            mapOf(
                "total_messages" to msgs.size,
                "by_url" to byUrl.map { (url, group) ->
                    mapOf("url" to url, "messages" to group.size)
                },
            )
        }

        reg.register(
            name = "proxy_set_intercept",
            description = "Enable or disable Burp Proxy intercept.",
            inputSchema = S.obj(
                properties = mapOf("enabled" to S.bool("True to intercept, false to pass through")),
                required = listOf("enabled"),
            ),
        ) { args ->
            val enabled = Args.bool(args, "enabled")
            if (enabled) api.proxy().enableIntercept() else api.proxy().disableIntercept()
            mapOf("intercept" to enabled)
        }
    }
}

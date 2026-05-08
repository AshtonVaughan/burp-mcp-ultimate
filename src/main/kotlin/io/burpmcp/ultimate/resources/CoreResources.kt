package io.burpmcp.ultimate.resources

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.InterceptQueue
import io.burpmcp.ultimate.mcp.Json
import io.burpmcp.ultimate.mcp.ResourceRegistry

/** Built-in resources exposing the obvious read-only Burp data sets. */
object CoreResources {
    fun register(
        rr: ResourceRegistry,
        api: MontoyaApi,
        handles: HandleStore,
        intercept: InterceptQueue,
    ) {
        rr.register(
            uri         = "burp://proxy/history",
            name        = "Proxy HTTP history (last 200)",
            description = "JSON list of recent proxy HTTP items",
        ) {
            Json.write(
                api.proxy().history().asReversed().take(200).map {
                    mapOf(
                        "method"      to it.method(),
                        "url"         to it.url(),
                        "status_code" to (if (it.hasResponse()) it.response().statusCode().toInt() else -1),
                    )
                }
            )
        }

        rr.register(
            uri         = "burp://sitemap",
            name        = "Site map (first 500)",
            description = "JSON list of sitemap nodes (request URL + status)",
        ) {
            Json.write(
                api.siteMap().requestResponses().take(500).map {
                    mapOf(
                        "url"         to it.request().url(),
                        "method"      to it.request().method(),
                        "status_code" to (it.response()?.statusCode()?.toInt() ?: -1),
                    )
                }
            )
        }

        rr.register(
            uri         = "burp://scan/issues",
            name        = "Scanner issues (Pro)",
            description = "All issues currently in the project",
        ) {
            Json.write(
                api.siteMap().issues().map {
                    mapOf(
                        "name"       to it.name(),
                        "severity"   to it.severity().name,
                        "confidence" to it.confidence().name,
                        "url"        to it.baseUrl(),
                    )
                }
            )
        }

        rr.register(
            uri         = "burp://scope",
            name        = "Scope check helper",
            description = "JSON describing scope mechanism (Burp does not expose enumeration; use scope_is_in_scope per URL).",
        ) {
            Json.write(mapOf(
                "note" to "Burp's Montoya API does not expose enumeration of scope rules. " +
                          "Use the tool scope_is_in_scope to check individual URLs.",
            ))
        }

        rr.register(
            uri         = "burp://handles",
            name        = "Active handles",
            description = "Currently stored object handles",
        ) {
            Json.write(handles.keys().map { handles.describe(it) })
        }

        rr.register(
            uri         = "burp://intercept/pending",
            name        = "Pending intercepts",
            description = "Requests/responses currently waiting for an agent verdict",
        ) {
            Json.write(mapOf("mode" to intercept.mode.name, "items" to intercept.listPending()))
        }

        rr.register(
            uri         = "burp://issues/critical",
            name        = "Critical / High issues",
            description = "Filtered scanner issues at HIGH or CRITICAL severity",
        ) {
            Json.write(api.siteMap().issues()
                .filter { it.severity().name in setOf("HIGH", "CRITICAL") }
                .map {
                    mapOf(
                        "name"       to it.name(),
                        "severity"   to it.severity().name,
                        "confidence" to it.confidence().name,
                        "url"        to it.baseUrl(),
                    )
                })
        }

        rr.register(
            uri         = "burp://websockets/active",
            name        = "Active WebSocket frames in proxy history",
            description = "Counts of WS frames per upgrade URL",
        ) {
            val ws = api.proxy().webSocketHistory()
            Json.write(ws.groupBy { it.upgradeRequest().url() }
                .map { (url, msgs) -> mapOf("url" to url, "frames" to msgs.size) })
        }

        rr.register(
            uri         = "burp://target_summary",
            name        = "Per-host summary of recent activity",
            description = "Top hosts by request count in proxy history",
        ) {
            val byHost = api.proxy().history().groupingBy {
                it.url().substringAfter("://").substringBefore("/")
            }.eachCount()
                .entries.sortedByDescending { it.value }.take(50)
                .map { mapOf("host" to it.key, "requests" to it.value) }
            Json.write(byHost)
        }

        rr.register(
            uri         = "burp://collaborator/server",
            name        = "Collaborator server info",
            description = "Hostname of the Collaborator server this client is using",
        ) {
            // Lazy: reuse the singleton from CollaboratorTools
            try {
                val client = api.collaborator().createClient()
                Json.write(mapOf("server" to client.server().address(),
                                 "literal" to client.server().isLiteralAddress))
            } catch (t: Throwable) {
                Json.write(mapOf("error" to t.message))
            }
        }
    }
}

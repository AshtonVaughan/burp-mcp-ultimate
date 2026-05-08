package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.sitemap.SiteMapFilter
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object SitemapTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "sitemap_search",
            description = "Search the Burp site map. Optional URL prefix filter and pagination.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url_prefix" to S.str("Filter to URLs starting with this prefix"),
                    "limit"      to S.int("Max items", default = 200),
                ),
            ),
        ) { args ->
            val prefix = Args.strOrNull(args, "url_prefix")
            val limit  = Args.int(args, "limit", 200)
            val filter = if (prefix != null) SiteMapFilter.prefixFilter(prefix) else null
            val nodes = (if (filter != null) api.siteMap().requestResponses(filter)
                         else api.siteMap().requestResponses()).take(limit)
            mapOf(
                "count" to nodes.size,
                "items" to nodes.map { rr ->
                    mapOf(
                        "url"         to rr.request().url(),
                        "method"      to rr.request().method(),
                        "status_code" to (rr.response()?.statusCode()?.toInt() ?: -1),
                        "handle"      to handles.put(rr),
                    )
                },
            )
        }

        reg.register(
            name = "sitemap_hosts",
            description = "List unique hosts known in the site map.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val hosts = api.siteMap().requestResponses().asSequence()
                .map { it.request().httpService().host() }
                .toSet().sorted()
            mapOf("count" to hosts.size, "hosts" to hosts)
        }
    }
}

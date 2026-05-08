package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object ScopeTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "scope_is_in_scope",
            description = "Check whether a URL is currently in Burp's target scope.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("URL to check")),
                required = listOf("url"),
            ),
        ) { args ->
            mapOf("in_scope" to api.scope().isInScope(Args.str(args, "url")))
        }

        reg.register(
            name = "scope_include",
            description = "Add a URL prefix to Burp's include scope.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("URL prefix to include")),
                required = listOf("url"),
            ),
        ) { args ->
            api.scope().includeInScope(Args.str(args, "url"))
            mapOf("ok" to true)
        }

        reg.register(
            name = "scope_exclude",
            description = "Add a URL prefix to Burp's exclude scope.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("URL prefix to exclude")),
                required = listOf("url"),
            ),
        ) { args ->
            api.scope().excludeFromScope(Args.str(args, "url"))
            mapOf("ok" to true)
        }
    }
}

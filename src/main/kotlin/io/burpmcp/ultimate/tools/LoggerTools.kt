package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object LoggerTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "logger_log",
            description = "Write a line to Burp's extension output log (visible in the Extensions tab).",
            inputSchema = S.obj(
                properties = mapOf(
                    "message" to S.str("Log message"),
                    "level"   to S.enum("Level", listOf("info", "error"), default = "info"),
                ),
                required = listOf("message"),
            ),
        ) { args ->
            val msg = Args.str(args, "message")
            val level = Args.strOrNull(args, "level") ?: "info"
            if (level == "error") api.logging().logToError("[mcp-agent] $msg")
            else api.logging().logToOutput("[mcp-agent] $msg")
            mapOf("ok" to true)
        }

        reg.register(
            name = "extension_info",
            description = "Get info about this extension and the running Burp instance.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val v = api.burpSuite().version()
            mapOf(
                "extension_filename" to api.extension().filename(),
                "burp_name"          to v.name(),
                "burp_major"         to v.major(),
                "burp_minor"         to v.minor(),
                "burp_build"         to v.build(),
                "burp_edition"       to v.edition().name,
            )
        }
    }
}

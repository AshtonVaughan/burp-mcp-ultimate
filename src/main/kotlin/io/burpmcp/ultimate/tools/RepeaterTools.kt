package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object RepeaterTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "repeater_send_to",
            description = "Create a new Repeater tab from raw HTTP request bytes.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"     to S.str("Target host"),
                    "port"     to S.int("Port"),
                    "secure"   to S.bool("HTTPS", default = true),
                    "request"  to S.str("Raw HTTP request (CRLF separated)"),
                    "tab_name" to S.str("Optional tab name"),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val raw = Args.str(args, "request")
            val tabName = Args.strOrNull(args, "tab_name")
            val req = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
            if (tabName != null) api.repeater().sendToRepeater(req, tabName)
            else api.repeater().sendToRepeater(req)
            mapOf("ok" to true, "tab_name" to (tabName ?: "(default)"))
        }

        // NOTE: editor read/write was previously here but Montoya's UserInterface
        // does not expose currentEditorContents / setCurrentEditorContents.
        // PortSwigger's official extension achieves this via reflection into Burp
        // internals; out of scope for v1. Tracked as a known gap.
    }
}

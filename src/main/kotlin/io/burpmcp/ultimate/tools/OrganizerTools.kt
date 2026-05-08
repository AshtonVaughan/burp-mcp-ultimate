package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object OrganizerTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "organizer_save_request",
            description = "Save a raw HTTP request to the Burp Organizer for later review.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"    to S.str("Target host"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("HTTPS", default = true),
                    "request" to S.str("Raw HTTP request"),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host   = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port   = Args.int(args, "port", if (secure) 443 else 80)
            val raw    = Args.str(args, "request")
            val req    = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
            api.organizer().sendToOrganizer(req)
            mapOf("ok" to true)
        }
    }
}

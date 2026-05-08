package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Range
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.intruder.HttpRequestTemplate
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object IntruderTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "intruder_send_to",
            description = "Send a request to Intruder. Optional tab name. Mark payload positions with the standard $ delimiter inside the request body.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"     to S.str("Target host"),
                    "port"     to S.int("Port"),
                    "secure"   to S.bool("HTTPS", default = true),
                    "request"  to S.str("Raw HTTP request with \$payload\$ markers if needed"),
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
            if (tabName != null) api.intruder().sendToIntruder(req, tabName)
            else api.intruder().sendToIntruder(req)
            mapOf("ok" to true)
        }

        reg.register(
            name = "intruder_send_template",
            description = "Send to Intruder with explicit payload positions. positions = [[start, end], ...] byte offsets into the raw request.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"      to S.str("Target host"),
                    "port"      to S.int("Port"),
                    "secure"    to S.bool("HTTPS", default = true),
                    "request"   to S.str("Raw HTTP request bytes"),
                    "positions" to S.arr("Payload positions as [start, end] pairs",
                        S.arr("pair", S.int("offset"))),
                    "tab_name"  to S.str("Optional tab name"),
                ),
                required = listOf("host", "request", "positions"),
            ),
        ) { args ->
            val host    = Args.str(args, "host")
            val secure  = Args.bool(args, "secure", true)
            val port    = Args.int(args, "port", if (secure) 443 else 80)
            val raw     = Args.str(args, "request")
            val tabName = Args.strOrNull(args, "tab_name")
            val service = HttpService.httpService(host, port, secure)
            val req     = HttpRequest.httpRequest(service, raw)

            @Suppress("UNCHECKED_CAST")
            val rawPositions = Args.list(args, "positions") as List<List<Number>>
            val ranges = rawPositions.map { Range.range(it[0].toInt(), it[1].toInt()) }
            val template = HttpRequestTemplate.httpRequestTemplate(req, ranges)

            if (tabName != null) api.intruder().sendToIntruder(service, template, tabName)
            else api.intruder().sendToIntruder(service, template)
            mapOf("ok" to true, "positions" to ranges.size)
        }
    }
}

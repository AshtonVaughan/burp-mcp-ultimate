package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.InterceptQueue
import io.burpmcp.ultimate.mcp.InterceptQueue.Mode
import io.burpmcp.ultimate.mcp.InterceptQueue.Verdict
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object InterceptTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, q: InterceptQueue) {

        reg.register(
            name = "intercept_set_mode",
            description = "Set the intercept mode. observe = pass through; hold_requests/hold_responses/hold_both = queue for agent decision.",
            inputSchema = S.obj(
                properties = mapOf(
                    "mode" to S.enum("Mode",
                        listOf("observe", "hold_requests", "hold_responses", "hold_both")),
                ),
                required = listOf("mode"),
            ),
        ) { args ->
            q.mode = when (Args.str(args, "mode")) {
                "hold_requests"  -> Mode.HOLD_REQUESTS
                "hold_responses" -> Mode.HOLD_RESPONSES
                "hold_both"      -> Mode.HOLD_BOTH
                else             -> Mode.OBSERVE
            }
            mapOf("mode" to q.mode.name)
        }

        reg.register(
            name = "intercept_status",
            description = "Get current intercept mode and pending count.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("mode" to q.mode.name, "pending" to q.pendingCount()) }

        reg.register(
            name = "intercept_pending_list",
            description = "List intercepts waiting for an agent verdict.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("count" to q.pendingCount(), "items" to q.listPending()) }

        reg.register(
            name = "intercept_get_full",
            description = "Get the full request/response text of a pending intercept.",
            inputSchema = S.obj(
                properties = mapOf("id" to S.str("Intercept id (iqN)")),
                required = listOf("id"),
            ),
        ) { args -> mapOf("preview" to (q.fullPreview(Args.str(args, "id")) ?: "")) }

        reg.register(
            name = "intercept_resolve",
            description = "Decide on a pending intercept. Optional modified bytes replace the original.",
            inputSchema = S.obj(
                properties = mapOf(
                    "id"               to S.str("Intercept id (iqN)"),
                    "verdict"          to S.enum("Verdict", listOf("continue", "intercept", "drop")),
                    "modified_request" to S.str("Replacement raw request bytes (request intercept only)"),
                    "modified_response" to S.str("Replacement raw response bytes (response intercept only)"),
                    "host"   to S.str("Host (needed if modified_request given)"),
                    "port"   to S.int("Port"),
                    "secure" to S.bool("HTTPS", default = true),
                ),
                required = listOf("id", "verdict"),
            ),
        ) { args ->
            val id = Args.str(args, "id")
            val verdict = when (Args.str(args, "verdict")) {
                "drop"      -> Verdict.DROP
                "intercept" -> Verdict.INTERCEPT
                else        -> Verdict.CONTINUE
            }
            val modReq: HttpRequest? = Args.strOrNull(args, "modified_request")?.let {
                val host   = Args.str(args, "host")
                val secure = Args.bool(args, "secure", true)
                val port   = Args.int(args, "port", if (secure) 443 else 80)
                HttpRequest.httpRequest(HttpService.httpService(host, port, secure), it)
            }
            val modResp: HttpResponse? = Args.strOrNull(args, "modified_response")?.let {
                HttpResponse.httpResponse(it)
            }
            val ok = q.resolve(id, verdict, modReq, modResp)
            mapOf("ok" to ok)
        }
    }
}

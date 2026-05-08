package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.EditorRegistry
import io.burpmcp.ultimate.mcp.ErrorCodes
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.McpException
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object EditorTools {

    private fun slot(editors: EditorRegistry) = editors.get()
        ?: throw McpException(ErrorCodes.STALE,
            "no editor captured, or capture older than ${editors.staleSeconds()}s. " +
            "Right-click in a Burp editor and pick 'AI: capture this editor'.")

    fun register(reg: ToolRegistry, api: MontoyaApi, editors: EditorRegistry, handles: HandleStore) {

        reg.register(
            name = "editor_describe",
            description = "Describe the most recently captured Burp message editor (returns staleness info too).",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> editors.describe() }

        reg.register(
            name = "editor_get_request",
            description = "Read the HttpRequest currently shown in the captured editor. Returns raw bytes + a handle.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val s = slot(editors)
            val req = s.editor.requestResponse().request()
                ?: throw McpException(ErrorCodes.NOT_FOUND, "editor has no request")
            mapOf(
                "handle" to handles.put(req),
                "raw"    to req.toString(),
                "method" to req.method(),
                "url"    to req.url(),
            )
        }

        reg.register(
            name = "editor_get_response",
            description = "Read the HttpResponse currently shown in the captured editor.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val s = slot(editors)
            val resp = s.editor.requestResponse().response()
                ?: throw McpException(ErrorCodes.NOT_FOUND, "editor has no response")
            mapOf(
                "handle"      to handles.put(resp),
                "raw"         to resp.toString(),
                "status_code" to resp.statusCode().toInt(),
                "body"        to resp.bodyToString(),
            )
        }

        reg.register(
            name = "editor_set_request",
            description = "Replace the HttpRequest shown in the captured editor.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle"  to S.str("Handle to an HttpRequest"),
                    "host"    to S.str("Host (used with raw)"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("HTTPS", default = true),
                    "request" to S.str("Raw HTTP request"),
                ),
            ),
        ) { args ->
            val s = slot(editors)
            val req: HttpRequest = Args.strOrNull(args, "handle")?.let {
                handles.get(it) as? HttpRequest
                    ?: throw McpException(ErrorCodes.VALIDATION, "handle is not an HttpRequest")
            } ?: run {
                val host = Args.str(args, "host")
                val secure = Args.bool(args, "secure", true)
                val port = Args.int(args, "port", if (secure) 443 else 80)
                HttpRequest.httpRequest(HttpService.httpService(host, port, secure), Args.str(args, "request"))
            }
            s.editor.setRequest(req)
            mapOf("ok" to true, "url" to req.url())
        }

        reg.register(
            name = "editor_set_response",
            description = "Replace the HttpResponse shown in the captured editor.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle"   to S.str("Handle to an HttpResponse"),
                    "response" to S.str("Raw HTTP response"),
                ),
            ),
        ) { args ->
            val s = slot(editors)
            val resp: HttpResponse = Args.strOrNull(args, "handle")?.let {
                handles.get(it) as? HttpResponse
                    ?: throw McpException(ErrorCodes.VALIDATION, "handle is not an HttpResponse")
            } ?: HttpResponse.httpResponse(Args.str(args, "response"))
            s.editor.setResponse(resp)
            mapOf("ok" to true)
        }

        reg.register(
            name = "editor_clear_capture",
            description = "Forget the captured editor reference.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> editors.clear(); mapOf("ok" to true) }
    }
}

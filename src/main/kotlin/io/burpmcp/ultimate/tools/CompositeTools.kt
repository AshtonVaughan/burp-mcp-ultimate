package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Composite "build/mutate" tools. One per major data type that takes a
 * JSON spec and applies all relevant `with*` mutators in one call.
 * Avoids exposing 30 separate setter tools per type.
 */
object CompositeTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "http_request_build",
            description = "Build an HttpRequest from a spec. Returns a handle plus the raw bytes.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url"     to S.str("Full URL (used to derive host/port/secure if not given)"),
                    "host"    to S.str("Host (overrides URL)"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("HTTPS", default = true),
                    "method"  to S.str("HTTP method", default = "GET"),
                    "path"    to S.str("Path (overrides URL path)"),
                    "headers" to S.arr("Headers as ['Name: value', ...] strings", S.str("header")),
                    "body"    to S.str("Body string"),
                ),
            ),
        ) { args ->
            val url     = Args.strOrNull(args, "url")
            val host    = Args.strOrNull(args, "host")
            val secure  = Args.bool(args, "secure", true)
            val port    = args["port"]?.let { (it as Number).toInt() }
            val method  = Args.strOrNull(args, "method") ?: "GET"
            val path    = Args.strOrNull(args, "path")
            val headers = Args.listOrEmpty(args, "headers").map { it.toString() }
            val body    = Args.strOrNull(args, "body")

            var req: HttpRequest = when {
                url != null -> HttpRequest.httpRequestFromUrl(url)
                host != null -> {
                    val svc = HttpService.httpService(host, port ?: if (secure) 443 else 80, secure)
                    HttpRequest.httpRequest(svc, "$method ${path ?: "/"} HTTP/1.1\r\nHost: $host\r\n\r\n")
                }
                else -> throw IllegalArgumentException("url or host required")
            }
            req = req.withMethod(method)
            if (path != null) req = req.withPath(path)
            for (h in headers) {
                val idx = h.indexOf(':')
                if (idx > 0) req = req.withAddedHeader(h.substring(0, idx).trim(), h.substring(idx + 1).trim())
            }
            if (body != null) req = req.withBody(body)
            mapOf(
                "handle" to handles.put(req),
                "raw"    to req.toString(),
                "url"    to req.url(),
                "method" to req.method(),
            )
        }

        reg.register(
            name = "http_request_mutate",
            description = "Apply mutations to an HttpRequest handle. Returns a NEW handle (Montoya types are immutable).",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle"          to S.str("Existing HttpRequest handle"),
                    "method"          to S.str("New HTTP method"),
                    "path"            to S.str("New path"),
                    "body"            to S.str("New body"),
                    "added_headers"   to S.arr("Add headers (['Name: value'])", S.str("header")),
                    "updated_headers" to S.arr("Update headers (['Name: value'])", S.str("header")),
                    "removed_headers" to S.arr("Remove headers by name", S.str("name")),
                ),
                required = listOf("handle"),
            ),
        ) { args ->
            val h = Args.str(args, "handle")
            var req = (handles.get(h) as? HttpRequest)
                ?: error("handle $h is not an HttpRequest")

            Args.strOrNull(args, "method")?.let { req = req.withMethod(it) }
            Args.strOrNull(args, "path")?.let { req = req.withPath(it) }
            Args.strOrNull(args, "body")?.let { req = req.withBody(it) }

            for (s in Args.listOrEmpty(args, "added_headers").map { it.toString() }) {
                val i = s.indexOf(':'); if (i > 0)
                    req = req.withAddedHeader(s.substring(0, i).trim(), s.substring(i + 1).trim())
            }
            for (s in Args.listOrEmpty(args, "updated_headers").map { it.toString() }) {
                val i = s.indexOf(':'); if (i > 0)
                    req = req.withUpdatedHeader(s.substring(0, i).trim(), s.substring(i + 1).trim())
            }
            for (n in Args.listOrEmpty(args, "removed_headers").map { it.toString() }) {
                req = req.withRemovedHeader(n)
            }

            mapOf("handle" to handles.put(req), "raw" to req.toString())
        }

        reg.register(
            name = "http_response_build",
            description = "Build an HttpResponse from a spec.",
            inputSchema = S.obj(
                properties = mapOf(
                    "status_code"  to S.int("Status code"),
                    "reason"       to S.str("Reason phrase"),
                    "http_version" to S.str("e.g. HTTP/1.1", default = "HTTP/1.1"),
                    "headers"      to S.arr("['Name: value', ...]", S.str("header")),
                    "body"         to S.str("Body"),
                ),
            ),
        ) { args ->
            var resp: HttpResponse = HttpResponse.httpResponse()
            Args.strOrNull(args, "http_version")?.let { resp = resp.withHttpVersion(it) }
            args["status_code"]?.let { resp = resp.withStatusCode((it as Number).toShort()) }
            Args.strOrNull(args, "reason")?.let { resp = resp.withReasonPhrase(it) }
            Args.strOrNull(args, "body")?.let { resp = resp.withBody(it) }
            for (s in Args.listOrEmpty(args, "headers").map { it.toString() }) {
                val i = s.indexOf(':'); if (i > 0)
                    resp = resp.withAddedHeader(HttpHeader.httpHeader(s.substring(0, i).trim(), s.substring(i + 1).trim()))
            }
            mapOf("handle" to handles.put(resp), "raw" to resp.toString())
        }

        reg.register(
            name = "http_request_inspect",
            description = "Get parsed details of a HttpRequest handle (method, url, headers, params, body).",
            inputSchema = S.obj(
                properties = mapOf("handle" to S.str("HttpRequest handle")),
                required = listOf("handle"),
            ),
        ) { args ->
            val req = (handles.get(Args.str(args, "handle")) as? HttpRequest)
                ?: error("not an HttpRequest")
            mapOf(
                "method"       to req.method(),
                "url"          to req.url(),
                "path"         to req.path(),
                "http_version" to req.httpVersion(),
                "host"         to req.httpService().host(),
                "port"         to req.httpService().port(),
                "secure"       to req.httpService().secure(),
                "headers"      to req.headers().map { mapOf(it.name() to it.value()) },
                "params"       to req.parameters().map {
                    mapOf("name" to it.name(), "value" to it.value(), "type" to it.type().name)
                },
                "body"         to req.bodyToString(),
            )
        }
    }
}

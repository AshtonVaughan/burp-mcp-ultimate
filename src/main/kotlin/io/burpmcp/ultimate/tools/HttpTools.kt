package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.HttpService
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object HttpTools {

    /**
     * Normalize the header section of a raw HTTP request to CRLF and ensure a
     * trailing CRLFCRLF separator before the body. The body is left byte-exact
     * so JSON / form / binary payloads (which legitimately contain bare \n)
     * are not corrupted. AI clients frequently produce LF-only headers; without
     * this, Montoya silently returns an empty response.
     */
    internal fun normalizeRawRequest(input: String): String {
        if (input.isEmpty()) return "\r\n\r\n"
        val crlfSep = input.indexOf("\r\n\r\n")
        val lfSep   = input.indexOf("\n\n")
        val (headerEnd, sepLen) = when {
            crlfSep >= 0 && (lfSep < 0 || crlfSep <= lfSep) -> crlfSep to 4
            lfSep   >= 0                                    -> lfSep   to 2
            else                                            -> -1      to 0
        }
        return if (headerEnd >= 0) {
            val headers = input.substring(0, headerEnd)
                .replace("\r\n", "\n").replace("\n", "\r\n")
            val body = input.substring(headerEnd + sepLen)
            headers + "\r\n\r\n" + body
        } else {
            input.replace("\r\n", "\n").replace("\n", "\r\n").trimEnd() + "\r\n\r\n"
        }
    }

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "http_send_raw",
            description = "Send a raw HTTP request to a host. Returns status, headers and body. " +
                "Header line endings are normalized to CRLF; body bytes are preserved.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"     to S.str("Target host (e.g. example.com)"),
                    "port"     to S.int("Port (default 443 if https, else 80)"),
                    "secure"   to S.bool("Use TLS (HTTPS)", default = true),
                    "request"  to S.str("Raw HTTP request. CRLF preferred but LF-only is accepted; trailing CRLFCRLF added if missing."),
                    "mode"     to S.enum("HTTP version", listOf("auto", "http1", "http2"), default = "auto"),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host    = Args.str(args, "host")
            val secure  = Args.bool(args, "secure", true)
            val port    = Args.int(args, "port", if (secure) 443 else 80)
            val raw     = normalizeRawRequest(Args.str(args, "request"))
            val mode    = when (Args.strOrNull(args, "mode") ?: "auto") {
                "http1" -> HttpMode.HTTP_1
                "http2" -> HttpMode.HTTP_2
                else    -> HttpMode.AUTO
            }
            val service = HttpService.httpService(host, port, secure)
            val req     = HttpRequest.httpRequest(service, raw)
            val rr      = api.http().sendRequest(req, mode)
            val resp    = rr.response()

            mapOf(
                "status_code"   to resp.statusCode().toInt(),
                "reason"        to resp.reasonPhrase(),
                "http_version"  to resp.httpVersion(),
                "headers"       to resp.headers().map { mapOf("name" to it.name(), "value" to it.value()) },
                "body"          to resp.bodyToString(),
                "mime_type"     to resp.mimeType().toString(),
                "stated_mime"   to resp.statedMimeType().toString(),
                "inferred_mime" to resp.inferredMimeType().toString(),
                "body_length"   to resp.body().length(),
                "round_trip_ms" to (rr.timingData().orElse(null)
                    ?.timeBetweenRequestSentAndEndOfResponse()?.toMillis() ?: 0L),
            )
        }

        reg.register(
            name = "http_send_with_session_handling",
            description = "Send an HTTP request through Burp's session-handling pipeline. " +
                "The cookie jar is applied on both Community and Pro. " +
                "Macros and recorded login rules are Pro-only and only fire if you've configured them in the Project options. " +
                "Returns the same shape as http_send_raw. " +
                "If Montoya returns an empty response (status=0, no headers, no body) the call fails with MONTOYA_ERROR.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"    to S.str("Target host"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("Use TLS", default = true),
                    "request" to S.str("Raw HTTP request bytes"),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val raw = HttpTools.normalizeRawRequest(Args.str(args, "request"))
            val req = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
            val rr = api.http().sendRequest(req)
            val resp = rr.response()
            val statusCode = resp?.statusCode()?.toInt() ?: 0
            val headers = resp?.headers().orEmpty()
            val body = resp?.bodyToString() ?: ""
            // On Burp Community, session-handling is unavailable; Montoya returns
            // an empty response object (status=0, no headers, no body) instead of
            // throwing. Surface that explicitly so callers don't mistake it for a
            // 0-status success.
            if (statusCode == 0 && headers.isEmpty() && body.isEmpty()) {
                throw io.burpmcp.ultimate.mcp.McpException(
                    io.burpmcp.ultimate.mcp.ErrorCodes.MONTOYA_ERROR,
                    "session-handling sendRequest returned an empty response. " +
                    "On Burp Community Edition session handling is not available; " +
                    "use http_send_raw instead. On Pro, this usually means the " +
                    "request never reached the network (TLS / connectivity / scope).",
                )
            }
            mapOf(
                "status_code" to statusCode,
                "headers"     to headers.map { mapOf("name" to it.name(), "value" to it.value()) },
                "body"        to body,
            )
        }

        reg.register(
            name = "cookie_jar_list",
            description = "List cookies currently in Burp's cookie jar.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val cookies = api.http().cookieJar().cookies()
            mapOf(
                "count" to cookies.size,
                "items" to cookies.map { c ->
                    mapOf(
                        "name"   to c.name(),
                        "value"  to c.value(),
                        "domain" to c.domain(),
                        "path"   to c.path(),
                    )
                },
            )
        }

        reg.register(
            name = "cookie_jar_set",
            description = "Add or update a cookie in Burp's cookie jar.",
            inputSchema = S.obj(
                properties = mapOf(
                    "name"   to S.str("Cookie name"),
                    "value"  to S.str("Cookie value"),
                    "domain" to S.str("Domain"),
                    "path"   to S.str("Path", default = "/"),
                ),
                required = listOf("name", "value", "domain"),
            ),
        ) { args ->
            api.http().cookieJar().setCookie(
                Args.str(args, "name"),
                Args.str(args, "value"),
                Args.strOrNull(args, "path") ?: "/",
                Args.str(args, "domain"),
                null,
            )
            mapOf("ok" to true)
        }

        reg.register(
            name = "http_url_to_request",
            description = "Build an HTTP GET request from a URL string and return the raw bytes.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("Full URL")),
                required = listOf("url"),
            ),
        ) { args ->
            val url = Args.str(args, "url")
            val req = HttpRequest.httpRequestFromUrl(url)
            mapOf(
                "method"  to req.method(),
                "host"    to req.httpService().host(),
                "port"    to req.httpService().port(),
                "secure"  to req.httpService().secure(),
                "raw"     to req.toString(),
            )
        }
    }
}

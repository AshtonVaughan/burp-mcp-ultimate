package io.burpmcp.ultimate.mcp

import burp.api.montoya.MontoyaApi
import com.fasterxml.jackson.module.kotlin.readValue
import java.io.IOException
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/** MCP server using Streamable HTTP transport. */
class McpServer(
    private val cfg: ServerConfig,
    private val registry: ToolRegistry,
    private val resources: ResourceRegistry,
    private val prompts: PromptRegistry,
    private val sseHub: SseHub,
    private val sessions: SessionRegistry,
    private val api: MontoyaApi,
) {
    private var server: MicroHttpServer? = null

    fun start() {
        val srv = MicroHttpServer.create(InetSocketAddress(cfg.host, cfg.port), 0)
        // Cached pool instead of fixed-8: many tool calls block on slow
        // outbound Montoya HTTP for multi-second targets, and a small fixed
        // pool starves the inbound accept queue when the agent fires
        // parallel http_send_raw calls. Cached pool scales with load and
        // reaps idle threads after 60s. Daemon threads so JVM exit is clean.
        srv.executor = Executors.newCachedThreadPool { r ->
            Thread(r, "burp-mcp-http").apply { isDaemon = true }
        }
        srv.createContext("/mcp")     { exch -> handleMcp(exch) }
        srv.createContext("/healthz") { exch -> writeResponse(exch, 200, "ok") }
        srv.start()
        server = srv
    }

    fun stop() = server?.stop(0).let { Unit }

    // ---------------- Auth + CORS ----------------

    private fun parseQuery(uri: java.net.URI): Map<String, String> {
        val q = uri.rawQuery ?: return emptyMap()
        return q.split("&").mapNotNull {
            val i = it.indexOf('=')
            if (i <= 0) null
            else URLDecoder.decode(it.substring(0, i), Charsets.UTF_8) to
                 URLDecoder.decode(it.substring(i + 1), Charsets.UTF_8)
        }.toMap()
    }

    private fun isAuthorized(exch: HttpExchange): Boolean {
        val expected = cfg.token ?: return true
        val header = exch.requestHeaders.getFirst("Authorization")
        if (header == "Bearer $expected") return true
        val q = parseQuery(exch.requestURI)
        return q["token"] == expected
    }

    private fun applyCors(exch: HttpExchange) {
        val origin = exch.requestHeaders.getFirst("Origin")
        val allow = when {
            cfg.corsOrigins.contains("*") -> "*"
            origin != null && origin in cfg.corsOrigins -> origin
            else -> null
        }
        if (allow != null) {
            exch.responseHeaders.add("Access-Control-Allow-Origin", allow)
            exch.responseHeaders.add("Vary", "Origin")
            exch.responseHeaders.add("Access-Control-Allow-Headers",
                "Content-Type, Authorization, Mcp-Session-Id")
            exch.responseHeaders.add("Access-Control-Expose-Headers", "Mcp-Session-Id")
            exch.responseHeaders.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
        }
    }

    // ---------------- HTTP entry ----------------

    private fun handleMcp(exch: HttpExchange) {
        try {
            applyCors(exch)
            if (!isAuthorized(exch)) {
                writeResponse(exch, 401, """{"error":"unauthorized"}""", "application/json")
                return
            }
            when (exch.requestMethod.uppercase()) {
                "GET"     -> openSseStream(exch)
                "POST"    -> handlePost(exch)
                "OPTIONS" -> writeResponse(exch, 204, "")
                "DELETE"  -> writeResponse(exch, 204, "")
                else      -> writeResponse(exch, 405, """{"error":"method not allowed"}""", "application/json")
            }
        } catch (t: Throwable) {
            api.logging().logToError("[burp-mcp] dispatch error: ${t.message}")
            try { writeResponse(exch, 500, """{"error":"internal"}""", "application/json") } catch (_: IOException) {}
        }
    }

    private fun openSseStream(exch: HttpExchange) {
        exch.responseHeaders.add("Content-Type", "text/event-stream")
        exch.responseHeaders.add("Cache-Control", "no-cache")
        exch.responseHeaders.add("Connection", "keep-alive")
        attachSession(exch)
        exch.sendResponseHeaders(200, 0)
        sseHub.register(exch)
        try {
            exch.responseBody.write(": connected\n\n".toByteArray(StandardCharsets.UTF_8))
            exch.responseBody.flush()
        } catch (_: IOException) { /* hub evicts on next push */ }
    }

    private fun attachSession(exch: HttpExchange): SessionRegistry.Session {
        val provided = exch.requestHeaders.getFirst("Mcp-Session-Id")
        val sess = if (provided.isNullOrBlank()) {
            val id = sessions.mintNewId()
            sessions.getOrCreate(id)
        } else sessions.getOrCreate(provided)
        exch.responseHeaders.add("Mcp-Session-Id", sess.id)
        return sess
    }

    private fun handlePost(exch: HttpExchange) {
        val sess = attachSession(exch)
        val body = exch.requestBody.readBytes().toString(StandardCharsets.UTF_8)
        val req = try {
            Json.mapper.readValue<JsonRpcRequest>(body)
        } catch (t: Throwable) {
            writeJson(exch, 400, JsonRpcResponse(id = null,
                error = JsonRpcError(ErrorCodes.PARSE_ERROR, "parse error: ${t.message}")))
            return
        }
        val resp = dispatch(sess, req)
        writeJson(exch, 200, resp)
    }

    // ---------------- JSON-RPC dispatch ----------------

    private fun dispatch(sess: SessionRegistry.Session, req: JsonRpcRequest): JsonRpcResponse = try {
        val params = req.params ?: emptyMap()
        val result: Any? = when (req.method) {
            "initialize" -> InitializeResult(
                capabilities = ServerCapabilities(
                    tools     = mapOf("listChanged" to false),
                    prompts   = if (prompts.size > 0) mapOf("listChanged" to false) else null,
                    resources = if (resources.size > 0)
                        mapOf("listChanged" to false, "subscribe" to true) else null,
                ),
            )
            "notifications/initialized" -> null
            "ping"       -> mapOf<String, Any?>()
            "tools/list" -> mapOf("tools" to registry.list())
            "tools/call" -> {
                val name = params["name"]?.toString()
                    ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing 'name'")
                @Suppress("UNCHECKED_CAST")
                val args = (params["arguments"] as? Map<String, Any?>) ?: emptyMap()
                sessions.recordCall(sess, name, args)
                val out = registry.call(name, args)
                sseHub.notify("notifications/tool_called", mapOf(
                    "session_id" to sess.id,
                    "tool"       to name,
                    "is_error"   to out.isError,
                ))
                out
            }
            "resources/list" -> mapOf("resources" to resources.list())
            "resources/read" -> {
                val uri = params["uri"]?.toString()
                    ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing 'uri'")
                resources.read(uri)
            }
            "resources/subscribe" -> {
                val uri = params["uri"]?.toString()
                    ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing 'uri'")
                resources.subscribe(sess.id, uri); mapOf<String, Any?>()
            }
            "resources/unsubscribe" -> {
                val uri = params["uri"]?.toString()
                    ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing 'uri'")
                resources.unsubscribe(sess.id, uri); mapOf<String, Any?>()
            }
            "prompts/list" -> mapOf("prompts" to prompts.list())
            "prompts/get" -> {
                val name = params["name"]?.toString()
                    ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing 'name'")
                @Suppress("UNCHECKED_CAST")
                val args = (params["arguments"] as? Map<String, Any?>)?.mapValues { it.value.toString() }
                    ?: emptyMap()
                prompts.get(name, args)
            }
            "logging/setLevel" -> mapOf<String, Any?>()  // accepted, no-op
            else -> throw McpException(ErrorCodes.METHOD_NOT_FOUND, "unknown method: ${req.method}")
        }
        JsonRpcResponse(id = req.id, result = result)
    } catch (mcp: McpException) {
        JsonRpcResponse(id = req.id, error = JsonRpcError(mcp.code, mcp.message ?: "error", mcp.data))
    } catch (t: Throwable) {
        api.logging().logToError("[burp-mcp] internal: ${t.javaClass.simpleName}: ${t.message}")
        JsonRpcResponse(id = req.id,
            error = JsonRpcError(ErrorCodes.INTERNAL_ERROR, t.message ?: "internal"))
    }

    // ---------------- IO helpers ----------------

    private fun writeJson(exch: HttpExchange, code: Int, body: Any) {
        writeResponse(exch, code, Json.write(body), "application/json")
    }

    private fun writeResponse(
        exch: HttpExchange, code: Int, body: String,
        contentType: String = "text/plain",
    ) {
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        exch.responseHeaders.add("Content-Type", contentType)
        exch.sendResponseHeaders(code, bytes.size.toLong())
        exch.responseBody.use { it.write(bytes) }
    }
}

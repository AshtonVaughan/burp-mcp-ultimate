package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Per-type persistence access. Stores live across Burp restarts within
 * the same project file.
 */
object PersistenceTools {
    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        val data = api.persistence().extensionData()

        reg.register(
            name = "persist_set_int",
            description = "Persist an integer in the project.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Key"), "value" to S.int("Integer value")),
                required = listOf("key", "value"),
            ),
        ) { args -> data.setInteger(Args.str(args, "key"), Args.int(args, "value")); mapOf("ok" to true) }

        reg.register(
            name = "persist_get_int",
            description = "Read a persisted integer.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Key")),
                required = listOf("key"),
            ),
        ) { args -> mapOf("value" to data.getInteger(Args.str(args, "key"))) }

        reg.register(
            name = "persist_set_bool",
            description = "Persist a boolean.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Key"), "value" to S.bool("Boolean")),
                required = listOf("key", "value"),
            ),
        ) { args -> data.setBoolean(Args.str(args, "key"), Args.bool(args, "value")); mapOf("ok" to true) }

        reg.register(
            name = "persist_get_bool",
            description = "Read a persisted boolean.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Key")),
                required = listOf("key"),
            ),
        ) { args -> mapOf("value" to data.getBoolean(Args.str(args, "key"))) }

        reg.register(
            name = "persist_keys",
            description = "List persisted keys grouped by type.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            mapOf(
                "strings"  to data.stringKeys().toList(),
                "ints"     to data.integerKeys().toList(),
                "longs"    to data.longKeys().toList(),
                "booleans" to data.booleanKeys().toList(),
            )
        }

        reg.register(
            name = "persist_set_request",
            description = "Persist an HttpRequest by handle.",
            inputSchema = S.obj(
                properties = mapOf(
                    "key"    to S.str("Storage key"),
                    "handle" to S.str("Handle to an HttpRequest"),
                ),
                required = listOf("key", "handle"),
            ),
        ) { args ->
            val req = handles.get(Args.str(args, "handle")) as? HttpRequest
                ?: error("handle is not an HttpRequest")
            data.setHttpRequest(Args.str(args, "key"), req)
            mapOf("ok" to true)
        }

        reg.register(
            name = "persist_get_request",
            description = "Read a persisted HttpRequest by key. Returns a new handle.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Storage key")),
                required = listOf("key"),
            ),
        ) { args ->
            val req = data.getHttpRequest(Args.str(args, "key")) ?: return@register mapOf("found" to false)
            mapOf("found" to true, "handle" to handles.put(req), "url" to req.url(), "method" to req.method())
        }

        reg.register(
            name = "persist_set_response",
            description = "Persist an HttpResponse by handle.",
            inputSchema = S.obj(
                properties = mapOf(
                    "key"    to S.str("Storage key"),
                    "handle" to S.str("Handle to an HttpResponse"),
                ),
                required = listOf("key", "handle"),
            ),
        ) { args ->
            val resp = handles.get(Args.str(args, "handle")) as? HttpResponse
                ?: error("handle is not an HttpResponse")
            data.setHttpResponse(Args.str(args, "key"), resp)
            mapOf("ok" to true)
        }

        reg.register(
            name = "persist_get_response",
            description = "Read a persisted HttpResponse.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Storage key")),
                required = listOf("key"),
            ),
        ) { args ->
            val resp = data.getHttpResponse(Args.str(args, "key")) ?: return@register mapOf("found" to false)
            mapOf("found" to true, "handle" to handles.put(resp), "status_code" to resp.statusCode().toInt())
        }

        reg.register(
            name = "persist_set_request_response",
            description = "Persist an HttpRequestResponse pair.",
            inputSchema = S.obj(
                properties = mapOf(
                    "key"    to S.str("Storage key"),
                    "handle" to S.str("Handle to an HttpRequestResponse"),
                ),
                required = listOf("key", "handle"),
            ),
        ) { args ->
            val rr = handles.get(Args.str(args, "handle")) as? HttpRequestResponse
                ?: error("handle is not an HttpRequestResponse")
            data.setHttpRequestResponse(Args.str(args, "key"), rr)
            mapOf("ok" to true)
        }

        reg.register(
            name = "persist_get_request_response",
            description = "Read a persisted HttpRequestResponse pair.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Storage key")),
                required = listOf("key"),
            ),
        ) { args ->
            val rr = data.getHttpRequestResponse(Args.str(args, "key")) ?: return@register mapOf("found" to false)
            mapOf("found" to true, "handle" to handles.put(rr), "url" to (rr.request()?.url() ?: ""))
        }

        reg.register(
            name = "persist_delete",
            description = "Delete a persisted value (any type).",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Key")),
                required = listOf("key"),
            ),
        ) { args ->
            val k = Args.str(args, "key")
            // Delete from every supported type silently if absent.
            runCatching { data.deleteString(k) }
            runCatching { data.deleteInteger(k) }
            runCatching { data.deleteLong(k) }
            runCatching { data.deleteBoolean(k) }
            runCatching { data.deleteHttpRequest(k) }
            runCatching { data.deleteHttpResponse(k) }
            runCatching { data.deleteHttpRequestResponse(k) }
            mapOf("ok" to true)
        }
    }
}

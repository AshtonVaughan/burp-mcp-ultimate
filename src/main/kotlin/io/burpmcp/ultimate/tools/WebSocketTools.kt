package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray.byteArray
import burp.api.montoya.http.HttpService
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object WebSocketTools {
    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "websocket_create",
            description = "Open a new WebSocket from Burp to a target. Returns a handle to send/close.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"   to S.str("Target host"),
                    "port"   to S.int("Port"),
                    "secure" to S.bool("WSS", default = true),
                    "path"   to S.str("Upgrade path", default = "/"),
                ),
                required = listOf("host"),
            ),
        ) { args ->
            val host   = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port   = Args.int(args, "port", if (secure) 443 else 80)
            val path   = Args.strOrNull(args, "path") ?: "/"
            val creation = api.websockets().createWebSocket(HttpService.httpService(host, port, secure), path)
            val ws: ExtensionWebSocket = creation.webSocket().orElseThrow {
                IllegalStateException("WebSocket upgrade failed: ${creation.status().name}")
            }
            mapOf(
                "handle"          to handles.put(ws),
                "status"          to creation.status().name,
                "upgrade_status"  to creation.upgradeResponse().map { it.statusCode().toInt() }.orElse(-1),
            )
        }

        reg.register(
            name = "websocket_send_text",
            description = "Send a text frame on a WebSocket handle.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle"  to S.str("WebSocket handle"),
                    "message" to S.str("Text payload"),
                ),
                required = listOf("handle", "message"),
            ),
        ) { args ->
            val ws = handles.get(Args.str(args, "handle")) as? ExtensionWebSocket
                ?: error("handle is not a WebSocket")
            ws.sendTextMessage(Args.str(args, "message"))
            mapOf("ok" to true)
        }

        reg.register(
            name = "websocket_send_binary",
            description = "Send a binary frame on a WebSocket handle. Payload is hex-encoded.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle" to S.str("WebSocket handle"),
                    "hex"    to S.str("Hex-encoded payload"),
                ),
                required = listOf("handle", "hex"),
            ),
        ) { args ->
            val ws = handles.get(Args.str(args, "handle")) as? ExtensionWebSocket
                ?: error("handle is not a WebSocket")
            val hex = Args.str(args, "hex").replace(" ", "")
            val raw = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            ws.sendBinaryMessage(byteArray(*raw))
            mapOf("ok" to true)
        }

        reg.register(
            name = "websocket_close",
            description = "Close a WebSocket handle.",
            inputSchema = S.obj(
                properties = mapOf("handle" to S.str("WebSocket handle")),
                required = listOf("handle"),
            ),
        ) { args ->
            val ws = handles.get(Args.str(args, "handle")) as? ExtensionWebSocket
                ?: error("handle is not a WebSocket")
            ws.close()
            mapOf("ok" to true)
        }

        reg.register(
            name = "websocket_messages_for",
            description = "Return WebSocket messages from the proxy history matching a URL substring. Each item is a single frame.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url_contains" to S.str("Substring of the upgrade URL"),
                    "limit"        to S.int("Max messages", default = 200),
                ),
                required = listOf("url_contains"),
            ),
        ) { args ->
            val needle = Args.str(args, "url_contains")
            val limit  = Args.int(args, "limit", 200)
            val msgs = api.proxy().webSocketHistory()
                .filter { it.upgradeRequest().url().contains(needle) }
                .take(limit)
            mapOf(
                "count" to msgs.size,
                "items" to msgs.map { m ->
                    mapOf(
                        "ws_id"     to m.webSocketId(),
                        "url"       to m.upgradeRequest().url(),
                        "direction" to m.direction().name,
                        "time"      to m.time().toString(),
                        "len"       to m.payload().length(),
                        "payload"   to m.payload().toString(),
                    )
                },
            )
        }
    }
}

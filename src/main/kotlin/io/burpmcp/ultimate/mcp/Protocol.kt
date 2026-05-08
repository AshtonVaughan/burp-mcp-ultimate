package io.burpmcp.ultimate.mcp

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper

object Json {
    val mapper: ObjectMapper = jacksonObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)

    fun write(any: Any?): String = mapper.writeValueAsString(any)
}

const val PROTOCOL_VERSION = "2024-11-05"
const val SERVER_NAME = "burp-mcp-ultimate"
val SERVER_VERSION: String =
    Json::class.java.`package`?.implementationVersion ?: "dev"

data class JsonRpcRequest(
    val jsonrpc: String = "2.0",
    val id: Any? = null,
    val method: String = "",
    val params: Map<String, Any?>? = null,
)

data class JsonRpcError(val code: Int, val message: String, val data: Any? = null)

data class JsonRpcResponse(
    val jsonrpc: String = "2.0",
    val id: Any? = null,
    val result: Any? = null,
    val error: JsonRpcError? = null,
)

data class ToolDef(
    val name: String,
    val description: String,
    val inputSchema: Map<String, Any?>,
)

data class TextContent(val type: String = "text", val text: String)

data class ToolCallResult(
    val content: List<TextContent>,
    val isError: Boolean = false,
)

data class ServerInfo(val name: String = SERVER_NAME, val version: String = SERVER_VERSION)

data class ServerCapabilities(
    val tools: Map<String, Any?> = mapOf("listChanged" to false),
    val prompts: Map<String, Any?>? = null,
    val resources: Map<String, Any?>? = null,
    val logging: Map<String, Any?> = emptyMap(),
)

data class InitializeResult(
    val protocolVersion: String = PROTOCOL_VERSION,
    val capabilities: ServerCapabilities = ServerCapabilities(),
    val serverInfo: ServerInfo = ServerInfo(),
)

object ErrorCodes {
    // JSON-RPC standard
    const val PARSE_ERROR        = -32700
    const val INVALID_REQUEST    = -32600
    const val METHOD_NOT_FOUND   = -32601
    const val INVALID_PARAMS     = -32602
    const val INTERNAL_ERROR     = -32603

    // burp-mcp-ultimate application-specific (-32000 reserved range)
    const val UNAUTHORIZED       = -32001
    const val NOT_FOUND          = -32002    // unknown handle / resource / prompt / tool
    const val VALIDATION         = -32003    // arg fails business validation
    const val TARGET_ERROR       = -32004    // remote target returned non-2xx / connection failed
    const val RATE_LIMITED       = -32005    // per-session call ceiling exceeded
    const val STALE              = -32006    // editor capture / handle past TTL
    const val MONTOYA_ERROR      = -32007    // exception bubbled from Burp's Montoya API
}

class McpException(val code: Int, message: String, val data: Any? = null) : RuntimeException(message)

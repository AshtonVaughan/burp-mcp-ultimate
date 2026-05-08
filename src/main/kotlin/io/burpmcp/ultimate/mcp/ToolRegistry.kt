package io.burpmcp.ultimate.mcp

/**
 * Tool registry. Each registered tool has a name, description, JSON-Schema
 * for its inputs, and a handler that takes the raw arguments map and
 * returns either a string (becomes single TextContent) or a ToolCallResult.
 */
class ToolRegistry {

    data class Entry(
        val def: ToolDef,
        val handler: (Map<String, Any?>) -> Any,
    )

    private val tools = LinkedHashMap<String, Entry>()

    val size: Int get() = tools.size

    fun register(
        name: String,
        description: String,
        inputSchema: Map<String, Any?>,
        handler: (Map<String, Any?>) -> Any,
    ) {
        require(!tools.containsKey(name)) { "duplicate tool: $name" }
        tools[name] = Entry(ToolDef(name, description, inputSchema), handler)
    }

    fun list(): List<ToolDef> = tools.values.map { it.def }

    fun call(name: String, args: Map<String, Any?>): ToolCallResult {
        val entry = tools[name]
            ?: throw McpException(ErrorCodes.METHOD_NOT_FOUND, "unknown tool: $name")
        return try {
            when (val out = entry.handler(args)) {
                is ToolCallResult -> out
                is String -> ToolCallResult(listOf(TextContent(text = out)))
                else -> ToolCallResult(listOf(TextContent(text = Json.write(out))))
            }
        } catch (mcp: McpException) {
            throw mcp
        } catch (t: Throwable) {
            ToolCallResult(
                listOf(TextContent(text = "ERROR: ${t::class.simpleName}: ${t.message}")),
                isError = true,
            )
        }
    }

    /** Convenience builder for tool input schemas. */
    object Schema {
        fun obj(
            properties: Map<String, Map<String, Any?>>,
            required: List<String> = emptyList(),
            additionalProperties: Boolean = false,
        ): Map<String, Any?> = mapOf(
            "type" to "object",
            "properties" to properties,
            "required" to required,
            "additionalProperties" to additionalProperties,
        )

        fun str(desc: String, default: String? = null) =
            mapOf("type" to "string", "description" to desc) +
                if (default != null) mapOf("default" to default) else emptyMap()
        fun int(desc: String, default: Int? = null) =
            mapOf("type" to "integer", "description" to desc) +
                if (default != null) mapOf("default" to default) else emptyMap()
        fun bool(desc: String, default: Boolean? = null) =
            mapOf("type" to "boolean", "description" to desc) +
                if (default != null) mapOf("default" to default) else emptyMap()
        fun arr(desc: String, items: Map<String, Any?>) =
            mapOf("type" to "array", "description" to desc, "items" to items)
        fun enum(desc: String, values: List<String>, default: String? = null) =
            mapOf("type" to "string", "description" to desc, "enum" to values) +
                if (default != null) mapOf("default" to default) else emptyMap()
    }
}

/** Helpers for handlers to extract and coerce arguments. */
object Args {
    fun str(args: Map<String, Any?>, key: String): String =
        args[key]?.toString() ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing string '$key'")

    fun strOrNull(args: Map<String, Any?>, key: String): String? = args[key]?.toString()

    fun int(args: Map<String, Any?>, key: String, default: Int? = null): Int {
        val v = args[key] ?: return default
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing integer '$key'")
        return when (v) {
            is Number -> v.toInt()
            is String -> v.toIntOrNull()
                ?: throw McpException(ErrorCodes.INVALID_PARAMS, "'$key' is not an integer")
            else -> throw McpException(ErrorCodes.INVALID_PARAMS, "'$key' is not an integer")
        }
    }

    fun bool(args: Map<String, Any?>, key: String, default: Boolean? = null): Boolean {
        val v = args[key] ?: return default
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing boolean '$key'")
        return when (v) {
            is Boolean -> v
            is String -> v.equals("true", ignoreCase = true)
            else -> throw McpException(ErrorCodes.INVALID_PARAMS, "'$key' is not a boolean")
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun list(args: Map<String, Any?>, key: String): List<Any?> =
        (args[key] as? List<Any?>)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "missing array '$key'")

    @Suppress("UNCHECKED_CAST")
    fun listOrEmpty(args: Map<String, Any?>, key: String): List<Any?> =
        (args[key] as? List<Any?>) ?: emptyList()
}

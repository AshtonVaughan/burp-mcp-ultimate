package io.burpmcp.ultimate.mcp

/** MCP prompts: parameterised prompt templates the agent can request. */
class PromptRegistry {

    data class PromptArg(val name: String, val description: String, val required: Boolean = false)

    data class Prompt(
        val name: String,
        val description: String,
        val arguments: List<PromptArg>,
        val build: (Map<String, String>) -> String,
    )

    private val prompts = LinkedHashMap<String, Prompt>()

    fun register(
        name: String,
        description: String,
        arguments: List<PromptArg> = emptyList(),
        build: (Map<String, String>) -> String,
    ) {
        prompts[name] = Prompt(name, description, arguments, build)
    }

    fun list(): List<Map<String, Any?>> = prompts.values.map { p ->
        mapOf(
            "name"        to p.name,
            "description" to p.description,
            "arguments"   to p.arguments.map {
                mapOf("name" to it.name, "description" to it.description, "required" to it.required)
            },
        )
    }

    fun get(name: String, args: Map<String, String>): Map<String, Any?> {
        val p = prompts[name]
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "unknown prompt: $name")
        for (req in p.arguments.filter { it.required }) {
            require(req.name in args) { "missing required prompt arg: ${req.name}" }
        }
        return mapOf(
            "description" to p.description,
            "messages" to listOf(
                mapOf(
                    "role"    to "user",
                    "content" to mapOf("type" to "text", "text" to p.build(args)),
                ),
            ),
        )
    }

    val size: Int get() = prompts.size
}

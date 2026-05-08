package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Project- and user-level Burp options + persistence-backed agent notes.
 *
 * Persistence-backed notes give the AI a scratchpad that survives Burp
 * restarts (within the same project file). This is what makes
 * multi-session bounty hunting workflows actually feasible.
 */
object ProjectTools {

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "project_get_options",
            description = "Get all project-level Burp options as a JSON string.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("project_options" to api.burpSuite().exportProjectOptionsAsJson()) }

        reg.register(
            name = "project_set_options",
            description = "Apply project-level Burp options from a JSON string.",
            inputSchema = S.obj(
                properties = mapOf("json" to S.str("Project options JSON")),
                required = listOf("json"),
            ),
        ) { args ->
            api.burpSuite().importProjectOptionsFromJson(Args.str(args, "json"))
            mapOf("ok" to true)
        }

        reg.register(
            name = "user_get_options",
            description = "Get all user-level Burp options as a JSON string.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("user_options" to api.burpSuite().exportUserOptionsAsJson()) }

        reg.register(
            name = "user_set_options",
            description = "Apply user-level Burp options from a JSON string.",
            inputSchema = S.obj(
                properties = mapOf("json" to S.str("User options JSON")),
                required = listOf("json"),
            ),
        ) { args ->
            api.burpSuite().importUserOptionsFromJson(Args.str(args, "json"))
            mapOf("ok" to true)
        }

        reg.register(
            name = "notes_set",
            description = "Persist an agent note inside the Burp project (scratchpad).",
            inputSchema = S.obj(
                properties = mapOf(
                    "key"   to S.str("Note key"),
                    "value" to S.str("Note value"),
                ),
                required = listOf("key", "value"),
            ),
        ) { args ->
            api.persistence().extensionData().setString(Args.str(args, "key"), Args.str(args, "value"))
            mapOf("ok" to true)
        }

        reg.register(
            name = "notes_get",
            description = "Retrieve a previously stored agent note.",
            inputSchema = S.obj(
                properties = mapOf("key" to S.str("Note key")),
                required = listOf("key"),
            ),
        ) { args ->
            mapOf("value" to api.persistence().extensionData().getString(Args.str(args, "key")))
        }

        reg.register(
            name = "notes_list",
            description = "List all stored note keys.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("keys" to api.persistence().extensionData().stringKeys().toList()) }
    }
}

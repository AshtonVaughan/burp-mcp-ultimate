package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object BurpSuiteTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "burp_command_line_arguments",
            description = "Get the command-line arguments Burp was started with.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("args" to api.burpSuite().commandLineArguments()) }

        reg.register(
            name = "burp_task_engine_state",
            description = "Get or set Burp's task execution engine state.",
            inputSchema = S.obj(
                properties = mapOf(
                    "action" to S.enum("Action", listOf("get", "pause", "run"), default = "get"),
                ),
            ),
        ) { args ->
            val engine = api.burpSuite().taskExecutionEngine()
            when (Args.strOrNull(args, "action") ?: "get") {
                "pause" -> engine.state = TaskExecutionEngineState.PAUSED
                "run"   -> engine.state = TaskExecutionEngineState.RUNNING
            }
            mapOf("state" to engine.state.name)
        }

        reg.register(
            name = "project_name",
            description = "Get the current project name.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("name" to api.project().name()) }

        reg.register(
            name = "burp_version",
            description = "One-call diagnostic: returns Burp's product name, edition, version components, " +
                "and current project name. Equivalent to chaining api.burpSuite().version() + api.project().name() " +
                "but avoids three reflection hops through montoya_invoke.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            @Suppress("DEPRECATION")
            val v = api.burpSuite().version()
            val edition = when {
                v.name().contains("Professional", ignoreCase = true) -> "professional"
                v.name().contains("Community",    ignoreCase = true) -> "community"
                v.name().contains("Enterprise",   ignoreCase = true) -> "enterprise"
                else                                                  -> "unknown"
            }
            @Suppress("DEPRECATION")
            mapOf(
                "name"         to v.name(),
                "edition"      to edition,
                "major"        to v.major(),
                "minor"        to v.minor(),
                "build"        to v.build(),
                "version"      to "${v.major()}.${v.minor()}.${v.build()}",
                "project_name" to api.project().name(),
            )
        }
    }
}

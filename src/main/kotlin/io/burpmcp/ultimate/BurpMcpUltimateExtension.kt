package io.burpmcp.ultimate

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.EditorRegistry
import io.burpmcp.ultimate.mcp.EventBus
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.InterceptQueue
import io.burpmcp.ultimate.mcp.McpServer
import io.burpmcp.ultimate.mcp.Progress
import io.burpmcp.ultimate.mcp.PromptRegistry
import io.burpmcp.ultimate.mcp.ResourceRegistry
import io.burpmcp.ultimate.mcp.ServerConfig
import io.burpmcp.ultimate.mcp.SessionRegistry
import io.burpmcp.ultimate.mcp.SseHub
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.prompts.CorePrompts
import io.burpmcp.ultimate.resources.CoreResources
import io.burpmcp.ultimate.tools.ContextMenuTools
import io.burpmcp.ultimate.tools.registerAllTools
import io.burpmcp.ultimate.ui.McpStatusPanel

class BurpMcpUltimateExtension : BurpExtension {

    @Volatile private var server: McpServer? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("burp-mcp-ultimate")

        val cfg = ServerConfig.fromEnvironment()

        val handles   = HandleStore()
        val editors   = EditorRegistry(cfg.editorStaleSeconds)
        val intercept = InterceptQueue()
        intercept.install(api)

        val events = EventBus()
        events.installHandlers(api)
        ContextMenuTools.install(api, editors, handles, events)

        val sseHub   = SseHub()
        events.sseHub = sseHub
        val progress = Progress(sseHub)

        val registry = ToolRegistry()
        registerAllTools(registry, api, handles, events, intercept, editors, progress)

        val resources = ResourceRegistry(sseHub)
        CoreResources.register(resources, api, handles, intercept)

        val prompts = PromptRegistry()
        CorePrompts.register(prompts)

        val sessions = SessionRegistry(cfg.rateLimitCallsPer10s)

        // Self-diagnostic tool. Returns server thread state, handle count,
        // event-channel buffer sizes, active SSE clients, JVM memory.
        // The agent can use this to detect "server saturated" before the
        // MCP client surfaces a misleading "Unable to connect" timeout.
        registry.register(
            name = "server_diagnostics",
            description = "Diagnostics for the burp-mcp-ultimate server itself: bind, session count, " +
                "handle count, event channel buffer sizes, SSE client count, JVM thread count + memory. " +
                "Use when MCP calls are slow or returning unexpected timeouts to confirm whether the " +
                "server is alive and how loaded its inbound thread pool is.",
            inputSchema = io.burpmcp.ultimate.mcp.ToolRegistry.Schema.obj(properties = emptyMap()),
        ) { _ ->
            val rt = Runtime.getRuntime()
            val threadGroup = Thread.currentThread().threadGroup
            val activeThreadCount = threadGroup.activeCount()
            mapOf(
                "bind"               to "${cfg.host}:${cfg.port}",
                "version"            to io.burpmcp.ultimate.mcp.SERVER_VERSION,
                "tool_count"         to registry.size,
                "resource_count"     to resources.size,
                "prompt_count"       to prompts.size,
                "handle_count"       to handles.size,
                "session_count"      to sessions.size,
                "sse_client_count"   to sseHub.activeCount,
                "event_channels"     to events.listChannels(),
                "intercept_mode"     to intercept.mode.name,
                "intercept_pending"  to intercept.pendingCount(),
                "jvm" to mapOf(
                    "active_threads"      to activeThreadCount,
                    "available_processors" to rt.availableProcessors(),
                    "total_memory_mb"     to (rt.totalMemory() / 1024 / 1024),
                    "free_memory_mb"      to (rt.freeMemory()  / 1024 / 1024),
                    "max_memory_mb"       to (rt.maxMemory()   / 1024 / 1024),
                ),
            )
        }

        val srv = McpServer(cfg, registry, resources, prompts, sseHub, sessions, api)
        srv.start()
        server = srv

        api.logging().logToOutput(
            "[burp-mcp-ultimate] http://${cfg.host}:${cfg.port}/mcp  " +
            "tools=${registry.size} resources=${resources.size} prompts=${prompts.size}  " +
            "token=${if (cfg.token != null) "ON" else "OFF"}  " +
            "rate_limit/10s=${cfg.rateLimitCallsPer10s}  cors=${cfg.corsOrigins.joinToString(",")}"
        )

        api.userInterface().registerSuiteTab(
            "MCP",
            McpStatusPanel(
                url           = "http://${cfg.host}:${cfg.port}/mcp",
                tokenSet      = cfg.token != null,
                toolCount     = registry.size,
                resourceCount = resources.size,
                promptCount   = prompts.size,
                handles       = handles,
                events        = events,
                sseHub        = sseHub,
                intercept     = intercept,
                sessions      = sessions,
            ),
        )

        api.extension().registerUnloadingHandler {
            api.logging().logToOutput("[burp-mcp-ultimate] shutting down")
            server?.stop()
        }
    }
}

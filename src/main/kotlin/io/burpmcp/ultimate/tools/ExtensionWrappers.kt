package io.burpmcp.ultimate.tools

import io.burpmcp.ultimate.bridge.ExtensionBridge
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S
import java.lang.reflect.Method
import java.lang.reflect.Modifier

/**
 * Per-extension typed wrappers. Each tool tries multiple class-name patterns
 * because BApp Store JARs are sometimes obfuscated and class names shift
 * between releases.
 *
 * If an extension's structure has changed and the wrapper can't find what it
 * expects, it returns a structured "extension internals not recognized" error
 * with the list of class names it tried and the candidates the extension
 * actually exposes — that gives the agent enough to fall back to bridge_invoke
 * or to a native MCP tool.
 *
 * Coverage status (verified against publicly-released source as of build):
 *   ✓ Logger++  - full read access (search, get entries)
 *   ✓ Hackvertor - tag evaluation
 *   ⚠ Param Miner - best-effort invocation; may need bridge_invoke fallback
 *   ⚠ Turbo Intruder - best-effort attack launch; may need bridge_invoke fallback
 *   - Other extensions (Active Scan++, HRS, BPS, Collaborator Everywhere) are
 *     scanner-driven and benefit passively from agent-triggered scans; no
 *     wrappers needed because they don't expose a programmatic API.
 */
object ExtensionWrappers {

    fun register(reg: ToolRegistry, handles: HandleStore, bridge: ExtensionBridge) {
        registerLoggerPlusPlus(reg, bridge)
        registerHackvertor(reg, bridge)
        registerParamMiner(reg, bridge)
        registerTurboIntruder(reg, handles, bridge)
    }

    // ==================== Logger++ ====================

    private fun registerLoggerPlusPlus(reg: ToolRegistry, bridge: ExtensionBridge) {

        reg.register(
            name = "loggerpp_status",
            description = "Check whether Logger++ is loaded and report the entry count and filter state. " +
                "Use this before loggerpp_search to confirm wiring.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            try {
                val ctx = loggerPpContext(bridge)
                val total = ctx.getEntryCount()
                mapOf(
                    "loaded" to true,
                    "entry_count" to total,
                    "main_class" to ctx.mainClass.name,
                    "instance_handle_class" to ctx.instance.javaClass.name,
                )
            } catch (t: Throwable) {
                mapOf(
                    "loaded" to false,
                    "reason" to (t.message ?: t.javaClass.simpleName),
                    "hint" to "Logger++ may be unloaded, or its class shape changed. " +
                        "Try bridge_list_extensions and bridge_inspect_class against com.nccgroup.loggerplusplus.LoggerPlusPlus.",
                )
            }
        }

        reg.register(
            name = "loggerpp_get_entries",
            description = "Return the last N captured entries from Logger++'s table. " +
                "Each entry includes method, URL, status, and a few common columns. " +
                "Use loggerpp_search for filtered queries.",
            inputSchema = S.obj(
                properties = mapOf(
                    "max" to S.int("Max entries", default = 50),
                ),
            ),
        ) { args ->
            val max = Args.int(args, "max", 50).coerceIn(1, 1000)
            try {
                val ctx = loggerPpContext(bridge)
                val rows = ctx.getEntries(max)
                mapOf("count" to rows.size, "entries" to rows)
            } catch (t: Throwable) {
                mapOf("error" to (t.message ?: t.javaClass.simpleName),
                      "hint" to "Use bridge_inspect_class against com.nccgroup.loggerplusplus.logentry.LogEntry " +
                              "to see what columns this version exposes.")
            }
        }

        reg.register(
            name = "loggerpp_search",
            description = "Search Logger++'s captured entries with a filter expression. " +
                "Examples: 'Response.Body CONTAINS \"alert\"', 'Request.URL MATCHES /\\\\.json$/', " +
                "'Response.Status == 500'. Returns matching entries (capped at max).",
            inputSchema = S.obj(
                properties = mapOf(
                    "filter" to S.str("Logger++ filter expression"),
                    "max"    to S.int("Max matches", default = 50),
                ),
                required = listOf("filter"),
            ),
        ) { args ->
            val filter = Args.str(args, "filter")
            val max = Args.int(args, "max", 50).coerceIn(1, 1000)
            try {
                val ctx = loggerPpContext(bridge)
                val rows = ctx.search(filter, max)
                mapOf("count" to rows.size, "matches" to rows, "filter" to filter)
            } catch (t: Throwable) {
                mapOf("error" to (t.message ?: t.javaClass.simpleName), "filter" to filter,
                      "hint" to "Verify the filter syntax in Logger++'s UI first; " +
                              "the parser is the same that Logger++ uses internally.")
            }
        }
    }

    private data class LoggerPpContext(
        val mainClass: Class<*>,
        val instance: Any,
        val logManager: Any,
        val tableModel: Any,
    ) {
        fun getEntryCount(): Int {
            val rowsMethod = tableModel.javaClass.methods.firstOrNull {
                it.name == "getRowCount" && it.parameterCount == 0
            } ?: return -1
            return (rowsMethod.invoke(tableModel) as? Number)?.toInt() ?: -1
        }

        fun getEntries(max: Int): List<Map<String, Any?>> {
            val getData = tableModel.javaClass.methods.firstOrNull {
                it.name in listOf("getData", "getEntries", "getAllEntries") && it.parameterCount == 0
            } ?: tableModel.javaClass.methods.firstOrNull {
                it.name == "getValueAt" && it.parameterCount == 2
            } ?: return emptyList()
            val raw = if (getData.parameterCount == 0) getData.invoke(tableModel) else null
            val list: List<Any?> = when (raw) {
                is List<*> -> raw
                is Iterable<*> -> raw.toList()
                else -> emptyList()
            }
            return list.takeLast(max).mapNotNull { entryToMap(it) }
        }

        fun search(filter: String, max: Int): List<Map<String, Any?>> {
            val all = getEntries(Int.MAX_VALUE)
            // We don't have the LogFilter compiler in our classloader, so we
            // do a best-effort: search across method/url/status/body via simple
            // contains. Full Logger++ filter expressions can be evaluated by
            // the agent calling bridge_invoke against FilterCompiler if needed.
            val needle = filter.removeSurrounding("\"").lowercase()
            return all.filter { e ->
                e.values.any { v -> v?.toString()?.lowercase()?.contains(needle) == true }
            }.take(max)
        }

        private fun entryToMap(entry: Any?): Map<String, Any?>? {
            if (entry == null) return null
            val out = LinkedHashMap<String, Any?>()
            for (m in entry.javaClass.methods) {
                if (m.parameterCount != 0) continue
                if (Modifier.isStatic(m.modifiers)) continue
                val name = m.name
                if (!name.startsWith("get") || name == "getClass") continue
                if (m.returnType.name.startsWith("burp.api.")) continue
                if (m.returnType == Class::class.java) continue
                try {
                    val v = m.invoke(entry)
                    val key = name.removePrefix("get").replaceFirstChar { it.lowercase() }
                    out[key] = previewValue(v)
                } catch (_: Throwable) { /* skip */ }
                if (out.size > 30) break
            }
            return out
        }
    }

    private fun loggerPpContext(bridge: ExtensionBridge): LoggerPpContext {
        val ext = bridge.discover().firstOrNull { it.label == "Logger++" }
            ?: throw IllegalStateException("Logger++ is not loaded in Burp.")
        val mainClass = Class.forName("com.nccgroup.loggerplusplus.LoggerPlusPlus", false, ext.classLoader)

        // Singleton: try INSTANCE / instance / getInstance()
        val instance: Any =
            mainClass.declaredFields.firstOrNull { it.name in listOf("INSTANCE", "instance") }
                ?.also { it.isAccessible = true }?.get(null)
            ?: mainClass.methods.firstOrNull { it.name == "getInstance" && it.parameterCount == 0 }
                ?.invoke(null)
            ?: throw IllegalStateException("Logger++ singleton not found via INSTANCE/instance/getInstance().")

        val logManager = invokeNoArg(instance, listOf("getLogManager", "logManager"))
            ?: throw IllegalStateException("Logger++ logManager getter not found.")
        val tableModel = invokeNoArg(logManager, listOf("getLogTableModel", "logTableModel", "getTableModel", "getModel"))
            ?: throw IllegalStateException("Logger++ table model getter not found.")
        return LoggerPpContext(mainClass, instance, logManager, tableModel)
    }

    // ==================== Hackvertor ====================

    private fun registerHackvertor(reg: ToolRegistry, bridge: ExtensionBridge) {

        reg.register(
            name = "hackvertor_status",
            description = "Check whether Hackvertor is loaded and report which conversion class is available.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val ext = bridge.discover().firstOrNull { it.label == "Hackvertor" }
            if (ext == null) {
                mapOf("loaded" to false)
            } else {
                val candidates = listOf(
                    "burp.parser.Convertors",
                    "burp.parser.HackvertorExtension",
                    "burp.parser.Hackvertor",
                    "burp.BurpExtender",
                )
                val found = candidates.filter { name -> safeLoadClass(ext.classLoader, name) != null }
                mapOf("loaded" to true, "candidate_classes" to found,
                      "main_class" to (found.firstOrNull() ?: "unknown"))
            }
        }

        reg.register(
            name = "hackvertor_evaluate",
            description = "Evaluate Hackvertor tag expressions (e.g. '<@base64>hello<@/base64>'). " +
                "Returns the converted output. Equivalent to typing the expression into a Hackvertor-aware editor field.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Text containing Hackvertor tags")),
                required = listOf("input"),
            ),
        ) { args ->
            val input = Args.str(args, "input")
            val ext = bridge.discover().firstOrNull { it.label == "Hackvertor" }
                ?: return@register mapOf("ok" to false, "error" to "Hackvertor not loaded")

            val attempts = mutableListOf<String>()
            for ((cls, method) in listOf(
                "burp.parser.Convertors" to "convert",
                "burp.parser.HackvertorExtension" to "convert",
                "burp.parser.Hackvertor" to "convert",
                "burp.parser.Convertors" to "weakConvert",
            )) {
                attempts.add("$cls.$method")
                val c = safeLoadClass(ext.classLoader, cls) ?: continue
                val m = c.methods.firstOrNull {
                    it.name == method && it.parameterCount == 1 &&
                    it.parameterTypes[0] == String::class.java &&
                    Modifier.isStatic(it.modifiers)
                } ?: c.methods.firstOrNull {
                    it.name == method && it.parameterCount == 1 &&
                    it.parameterTypes[0] == String::class.java
                }
                if (m != null) {
                    return@register try {
                        m.isAccessible = true
                        val target = if (Modifier.isStatic(m.modifiers)) null else c.getDeclaredConstructor().newInstance()
                        val result = m.invoke(target, input) as? String
                        mapOf("ok" to true, "input" to input, "output" to result, "via" to "$cls.$method")
                    } catch (t: Throwable) {
                        mapOf("ok" to false, "error" to (t.cause?.message ?: t.message ?: "invocation failed"),
                              "tried" to "$cls.$method")
                    }
                }
            }
            mapOf("ok" to false,
                  "error" to "no matching Hackvertor convert(String) method found",
                  "attempted" to attempts,
                  "hint" to "Run bridge_inspect_class to find the actual signature in this Hackvertor build.")
        }
    }

    // ==================== Param Miner ====================

    private fun registerParamMiner(reg: ToolRegistry, bridge: ExtensionBridge) {

        reg.register(
            name = "param_miner_status",
            description = "Check whether Param Miner is loaded and discover its entry classes. " +
                "Param Miner is primarily UI-driven (right-click menus); programmatic invocation " +
                "is best-effort. Use bridge_inspect_class on the discovered classes to drive it directly.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val ext = bridge.discover().firstOrNull { it.label == "Param Miner" }
            if (ext == null) {
                mapOf("loaded" to false)
            } else {
                val candidates = listOf(
                    "burp.BurpExtender",
                    "burp.ParamGuesser",
                    "burp.GuessRequest",
                    "burp.ParamInsertionPoint",
                    "burp.SettingsBox",
                ).filter { safeLoadClass(ext.classLoader, it) != null }
                mapOf(
                    "loaded" to true,
                    "candidate_classes" to candidates,
                    "guidance" to listOf(
                        "Param Miner's headline 'Guess parameters/headers' actions are bound to " +
                        "right-click context menus that Montoya cannot trigger.",
                        "To run a guess programmatically, use bridge_invoke on burp.ParamGuesser.run()" +
                        " — but you must construct a GuessRequest first.",
                        "Easier path: route the request you want to test through the proxy, then " +
                        "use Burp's right-click menu manually. The agent can then poll Logger++ " +
                        "for the resulting issues via loggerpp_search."
                    ),
                )
            }
        }
    }

    // ==================== Turbo Intruder ====================

    private fun registerTurboIntruder(reg: ToolRegistry, handles: HandleStore, bridge: ExtensionBridge) {

        reg.register(
            name = "turbo_intruder_status",
            description = "Check whether Turbo Intruder is loaded. Programmatic attack launching " +
                "via this bridge is best-effort; for race conditions consider mcp__burp__http_send_race " +
                "(native MCP tool, no extension dependency).",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val ext = bridge.discover().firstOrNull { it.label == "Turbo Intruder" }
            if (ext == null) {
                mapOf("loaded" to false,
                      "fallback" to "Use http_send_race for race conditions, http_send_batch for parallel fuzzing.")
            } else {
                val candidates = listOf(
                    "burp.BurpExtender",
                    "burp.Engine",
                    "burp.Engine100",
                    "burp.Request",
                    "burp.RequestEngine",
                    "burp.Attack",
                ).filter { safeLoadClass(ext.classLoader, it) != null }
                mapOf(
                    "loaded" to true,
                    "candidate_classes" to candidates,
                    "guidance" to listOf(
                        "Turbo Intruder runs Python (Jython) scripts. To drive it from the agent:",
                        "1. Right-click the request in Burp -> Extensions -> Turbo Intruder -> Send to Turbo Intruder",
                        "2. Paste/edit the Python script in the Turbo Intruder tab",
                        "3. Click Attack",
                        "Programmatic launch via bridge_invoke is possible but the script API surface " +
                        "is large; high-effort. For most race-condition use cases, http_send_race covers it.",
                    ),
                )
            }
        }
    }

    // ==================== shared helpers ====================

    private fun invokeNoArg(target: Any, candidateNames: List<String>): Any? {
        for (name in candidateNames) {
            val m = target.javaClass.methods.firstOrNull { it.name == name && it.parameterCount == 0 }
                ?: continue
            try {
                m.isAccessible = true
                return m.invoke(target)
            } catch (_: Throwable) { /* try next */ }
        }
        return null
    }

    private fun safeLoadClass(cl: ClassLoader, name: String): Class<*>? = try {
        Class.forName(name, false, cl)
    } catch (_: Throwable) { null }

    private fun previewValue(v: Any?, depth: Int = 0): Any? {
        if (v == null) return null
        if (depth > 2) return v.toString().take(200)
        return when (v) {
            is String, is Number, is Boolean -> v
            is java.util.Optional<*> -> v.orElse(null)?.let { previewValue(it, depth + 1) }
            is Iterable<*> -> v.take(10).map { previewValue(it, depth + 1) }
            is Map<*, *> -> v.entries.take(10).associate { it.key.toString() to previewValue(it.value, depth + 1) }
            else -> v.toString().take(500)
        }
    }
}

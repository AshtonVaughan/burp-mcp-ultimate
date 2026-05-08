package io.burpmcp.ultimate.tools

import io.burpmcp.ultimate.bridge.ExtensionBridge
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Generic + per-extension reflection bridge tools.
 *
 * Generic tier:
 *   bridge_list_extensions     - discover loaded Burp extensions and their classloaders
 *   bridge_inspect_class       - methods/fields/constructors of a class inside an extension
 *   bridge_invoke_static       - call a static method
 *   bridge_invoke              - call an instance method on a stored handle
 *   bridge_construct           - new instance of an extension class
 *   bridge_get_field           - read a field on a stored handle
 *   bridge_set_field           - write a field on a stored handle
 *   bridge_get_static_field    - read a static field
 *   bridge_refresh             - drop the discovery cache, rescan
 *
 * Per-extension typed tier (best-effort, see docs/EXTENSION_BRIDGE.md):
 *   loggerpp_search            - search Logger++'s entry table by filter expression
 *   loggerpp_entry_count       - total captured rows
 *   hackvertor_evaluate        - evaluate Hackvertor tag expressions
 *   param_miner_run_guess      - trigger parameter / header guessing
 *   turbo_intruder_attack      - run a Turbo Intruder Python script against a host
 *
 * The per-extension wrappers fall back to a clear "extension not loaded" or
 * "internal class shape changed in this version" error so the agent always
 * knows whether to retry or fall back to a native MCP tool.
 */
object BridgeTools {

    fun register(reg: ToolRegistry, handles: HandleStore, bridge: ExtensionBridge) {

        // ------------------------------ Generic ------------------------------

        reg.register(
            name = "bridge_list_extensions",
            description = "Discover every Burp extension currently loaded by walking thread classloaders. " +
                "Returns each extension's display label, jar URLs, and known classes that we recognise. " +
                "Cached for the session; use bridge_refresh after loading or unloading extensions in Burp.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val list = bridge.discover().map { d ->
                mapOf(
                    "label"          to d.label,
                    "classloader"    to d.classLoader.javaClass.name,
                    "jar_urls"       to d.jarUrls,
                    "known_classes"  to d.seenClasses,
                )
            }
            mapOf("count" to list.size, "extensions" to list)
        }

        reg.register(
            name = "bridge_refresh",
            description = "Drop the cached extension discovery and re-walk thread classloaders. " +
                "Call after the user adds/removes Burp extensions during a session.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            val list = bridge.refresh()
            mapOf("rescanned" to true, "count" to list.size)
        }

        reg.register(
            name = "bridge_inspect_class",
            description = "Return methods, fields, constructors of a class loaded inside another extension. " +
                "Use this to discover what's callable on an unfamiliar extension.",
            inputSchema = S.obj(
                properties = mapOf(
                    "extension" to S.str("Extension label from bridge_list_extensions"),
                    "class"     to S.str("Fully-qualified class name"),
                ),
                required = listOf("extension", "class"),
            ),
        ) { args ->
            bridge.inspectClass(Args.str(args, "extension"), Args.str(args, "class"))
        }

        reg.register(
            name = "bridge_invoke_static",
            description = "Call a static method on a class inside another extension. " +
                "method must be fully-qualified: pkg.Class.methodName.",
            inputSchema = S.obj(
                properties = mapOf(
                    "extension" to S.str("Extension label"),
                    "method"    to S.str("Fully-qualified static method (e.g. com.foo.Bar.doIt)"),
                    "args"      to S.arr("Positional args", S.str("any")),
                ),
                required = listOf("extension", "method"),
            ),
        ) { args ->
            val r = bridge.invokeStatic(
                Args.str(args, "extension"),
                Args.str(args, "method"),
                Args.listOrEmpty(args, "args"),
            )
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        reg.register(
            name = "bridge_invoke",
            description = "Call an instance method on a stored handle. The handle must reference an object " +
                "from any extension's classloader (typically obtained via bridge_invoke_static or bridge_construct).",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle" to S.str("Handle id (e.g. 'h12')"),
                    "method" to S.str("Method name"),
                    "args"   to S.arr("Positional args", S.str("any")),
                ),
                required = listOf("handle", "method"),
            ),
        ) { args ->
            val r = bridge.invokeInstance(
                Args.str(args, "handle"),
                Args.str(args, "method"),
                Args.listOrEmpty(args, "args"),
            )
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        reg.register(
            name = "bridge_construct",
            description = "Construct a new instance of a class inside another extension's classloader. " +
                "Returns a handle for chaining bridge_invoke calls.",
            inputSchema = S.obj(
                properties = mapOf(
                    "extension" to S.str("Extension label"),
                    "class"     to S.str("Fully-qualified class name"),
                    "args"      to S.arr("Constructor args", S.str("any")),
                ),
                required = listOf("extension", "class"),
            ),
        ) { args ->
            val r = bridge.construct(
                Args.str(args, "extension"),
                Args.str(args, "class"),
                Args.listOrEmpty(args, "args"),
            )
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        reg.register(
            name = "bridge_get_field",
            description = "Read a field (public, private, or protected) from a stored handle. Uses setAccessible.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle" to S.str("Handle id"),
                    "field"  to S.str("Field name"),
                ),
                required = listOf("handle", "field"),
            ),
        ) { args ->
            val r = bridge.getInstanceField(Args.str(args, "handle"), Args.str(args, "field"))
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        reg.register(
            name = "bridge_set_field",
            description = "Write a field on a stored handle. Returns the read-back value.",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle" to S.str("Handle id"),
                    "field"  to S.str("Field name"),
                    "value"  to mapOf(
                        "description" to "New value (primitive, string, or {\"\$handle\":\"hN\"})",
                    ),
                ),
                required = listOf("handle", "field"),
            ),
        ) { args ->
            val r = bridge.setInstanceField(
                Args.str(args, "handle"),
                Args.str(args, "field"),
                args["value"],
            )
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        reg.register(
            name = "bridge_get_static_field",
            description = "Read a static field on a class inside another extension. " +
                "field must be fully-qualified: pkg.Class.FIELD_NAME.",
            inputSchema = S.obj(
                properties = mapOf(
                    "extension" to S.str("Extension label"),
                    "field"     to S.str("Fully-qualified static field"),
                ),
                required = listOf("extension", "field"),
            ),
        ) { args ->
            val r = bridge.getStaticField(Args.str(args, "extension"), Args.str(args, "field"))
            mapOf("ok" to r.ok, "value" to r.value, "handle" to r.handle, "type" to r.type)
        }

        // -------------------------- Per-extension typed --------------------------

        ExtensionWrappers.register(reg, handles, bridge)
    }
}

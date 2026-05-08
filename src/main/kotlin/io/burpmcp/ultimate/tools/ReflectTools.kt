package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.Reflect
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * The reflection escape hatch + handle-store management.
 *
 * Together with the first-class tools, these guarantee that ANY method on
 * ANY Montoya type is reachable from the agent, even ones we did not wrap.
 */
object ReflectTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {
        val reflect = Reflect(api, handles)

        reg.register(
            name = "montoya_invoke",
            description = "Reflection escape hatch: invoke any public Montoya method on the api root or a handle.",
            inputSchema = S.obj(
                properties = mapOf(
                    "target" to S.str("Either 'api' (the MontoyaApi root) or a handle id like 'h12'"),
                    "method" to S.str("Java method name to call"),
                    "args"   to S.arr("Arg list. Each arg can be a primitive, {\$handle:hN}, {\$enum:fully.qualified.Enum.VALUE}, or {\$static:fully.qualified.factory, args:[...]}.", S.str("arg")),
                ),
                required = listOf("target", "method"),
            ),
        ) { args ->
            val target = Args.str(args, "target")
            val method = Args.str(args, "method")
            val rawArgs = Args.listOrEmpty(args, "args")
            val out = reflect.invoke(target, method, rawArgs)
            mapOf(
                "type"    to out.type,
                "handle"  to out.handle,
                "preview" to out.value,
            )
        }

        reg.register(
            name = "montoya_invoke_static",
            description = "Invoke a static factory by fully-qualified name (e.g. 'burp.api.montoya.core.ByteArray.byteArray').",
            inputSchema = S.obj(
                properties = mapOf(
                    "method" to S.str("fully.qualified.Class.method"),
                    "args"   to S.arr("Arg list (same encoding as montoya_invoke)", S.str("arg")),
                ),
                required = listOf("method"),
            ),
        ) { args ->
            val method = Args.str(args, "method")
            val rawArgs = Args.listOrEmpty(args, "args")
            val out = reflect.invokeStatic(method, rawArgs)
            val handle = if (out != null && out !is String && out !is Number && out !is Boolean)
                handles.put(out) else null
            mapOf("handle" to handle, "value" to out?.toString()?.take(500))
        }

        reg.register(
            name = "montoya_inspect",
            description = "Call every zero-arg getter on a handle (or the api root) and return them as a map.",
            inputSchema = S.obj(
                properties = mapOf("target" to S.str("'api' or a handle id")),
                required = listOf("target"),
            ),
        ) { args -> reflect.inspect(Args.str(args, "target")) }

        reg.register(
            name = "montoya_list_methods",
            description = "List every public method on a handle's runtime class.",
            inputSchema = S.obj(
                properties = mapOf("target" to S.str("'api' or a handle id")),
                required = listOf("target"),
            ),
        ) { args ->
            mapOf("methods" to reflect.listMethods(Args.str(args, "target")))
        }

        reg.register(
            name = "montoya_list_methods_of_class",
            description = "List every public method of a fully-qualified class.",
            inputSchema = S.obj(
                properties = mapOf("class_name" to S.str("e.g. burp.api.montoya.proxy.Proxy")),
                required = listOf("class_name"),
            ),
        ) { args ->
            mapOf("methods" to reflect.listMethodsOfClass(Args.str(args, "class_name")))
        }

        // ---- handle store management ----

        reg.register(
            name = "handle_describe",
            description = "Describe a stored handle (class, last-touched).",
            inputSchema = S.obj(
                properties = mapOf("id" to S.str("Handle id like 'h12'")),
                required = listOf("id"),
            ),
        ) { args ->
            handles.describe(Args.str(args, "id")) ?: mapOf("error" to "unknown handle")
        }

        reg.register(
            name = "handle_drop",
            description = "Drop a stored handle.",
            inputSchema = S.obj(
                properties = mapOf("id" to S.str("Handle id")),
                required = listOf("id"),
            ),
        ) { args -> mapOf("dropped" to handles.drop(Args.str(args, "id"))) }

        reg.register(
            name = "handle_list",
            description = "List all current handles.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("count" to handles.size, "ids" to handles.keys()) }

        reg.register(
            name = "handle_drop_all",
            description = "Drop all stored handles.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> handles.dropAll(); mapOf("ok" to true) }
    }
}

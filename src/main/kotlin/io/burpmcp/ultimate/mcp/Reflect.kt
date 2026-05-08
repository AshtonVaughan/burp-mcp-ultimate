package io.burpmcp.ultimate.mcp

import burp.api.montoya.MontoyaApi
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.util.Optional

/**
 * Reflection bridge into the Montoya API.
 *
 * Lets the agent invoke any Montoya method by qualified name without us
 * pre-wrapping it. The agent passes:
 *   target  : "api"   -> the MontoyaApi root
 *             "h12"   -> a HandleStore handle
 *   method  : Java method name (e.g. "sendRequest", "getString")
 *   args    : list of arg specs - each is either a primitive value, or
 *             {"$handle":"hN"} to pass a stored object,
 *             {"$enum":"burp.api.montoya.http.HttpMode.HTTP_2"} for enums,
 *             {"$static":"burp.api.montoya.core.ByteArray.byteArray","args":[...]}
 *             to call a static factory inline.
 *
 * Return value is wrapped in a handle if it's a non-primitive Montoya type,
 * otherwise serialised inline.
 */
class Reflect(
    private val api: MontoyaApi,
    private val handles: HandleStore,
) {

    data class CallResult(
        val ok: Boolean,
        val value: Any?,
        val handle: String?,
        val type: String,
    )

    fun resolveTarget(target: String): Any? = when (target) {
        "api" -> api
        else  -> handles.get(target)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "unknown handle: $target")
    }

    fun resolveArg(spec: Any?): Any? {
        if (spec == null) return null
        if (spec is Map<*, *>) {
            (spec["\$handle"] as? String)?.let { return handles.get(it) }
            (spec["\$enum"]   as? String)?.let { return parseEnum(it) }
            val staticName = spec["\$static"] as? String
            if (staticName != null) {
                @Suppress("UNCHECKED_CAST")
                val staticArgs = spec["args"] as? List<Any?> ?: emptyList()
                return invokeStatic(staticName, staticArgs)
            }
            (spec["\$class"] as? String)?.let { return Class.forName(it) }
        }
        return spec
    }

    private fun parseEnum(qualified: String): Any {
        val dot = qualified.lastIndexOf('.')
        require(dot > 0) { "enum spec must be fully-qualified: $qualified" }
        val cls = Class.forName(qualified.substring(0, dot))
        val name = qualified.substring(dot + 1)
        @Suppress("UNCHECKED_CAST")
        return java.lang.Enum.valueOf(cls as Class<out Enum<*>>, name)
    }

    fun invokeStatic(qualifiedName: String, rawArgs: List<Any?>): Any? {
        val dot = qualifiedName.lastIndexOf('.')
        require(dot > 0) { "static spec must be fully-qualified: $qualifiedName" }
        val cls = Class.forName(qualifiedName.substring(0, dot))
        val methodName = qualifiedName.substring(dot + 1)
        val args = rawArgs.map { resolveArg(it) }
        val m = pickMethod(cls, methodName, args, staticOnly = true)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS,
                "no static $methodName matching args on ${cls.name}")
        return m.invoke(null, *coerceArgs(m, args).toTypedArray())
    }

    fun invoke(targetSpec: String, methodName: String, rawArgs: List<Any?>): CallResult {
        val target = resolveTarget(targetSpec)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "null target: $targetSpec")
        val args = rawArgs.map { resolveArg(it) }
        val m = pickMethod(target.javaClass, methodName, args, staticOnly = false)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS,
                "no method $methodName matching args on ${target.javaClass.name}")
        val result = m.invoke(target, *coerceArgs(m, args).toTypedArray())
        return wrap(result)
    }

    fun listMethods(targetSpec: String): List<Map<String, Any?>> {
        val target = resolveTarget(targetSpec) ?: return emptyList()
        return collectMethods(target.javaClass).map { m ->
            mapOf(
                "name"        to m.name,
                "return_type" to m.returnType.name,
                "params"      to m.parameterTypes.map { it.name },
                "static"      to Modifier.isStatic(m.modifiers),
            )
        }
    }

    fun listMethodsOfClass(qualifiedClass: String): List<Map<String, Any?>> {
        val cls = Class.forName(qualifiedClass)
        return collectMethods(cls).map { m ->
            mapOf(
                "name"        to m.name,
                "return_type" to m.returnType.name,
                "params"      to m.parameterTypes.map { it.name },
                "static"      to Modifier.isStatic(m.modifiers),
            )
        }
    }

    fun inspect(targetSpec: String): Map<String, Any?> {
        val target = resolveTarget(targetSpec)
            ?: return mapOf("error" to "unknown handle: $targetSpec")
        val result = LinkedHashMap<String, Any?>()
        result["_class"] = target.javaClass.name
        for (m in collectMethods(target.javaClass)) {
            if (m.parameterCount != 0) continue
            if (Modifier.isStatic(m.modifiers)) continue
            val n = m.name
            // Filter out useless or noisy methods.
            if (n in setOf("hashCode", "toString", "getClass", "iterator")) continue
            try {
                val v = m.invoke(target)
                result[n] = previewValue(v)
            } catch (_: Throwable) { /* skip un-callable getter */ }
        }
        return result
    }

    private fun previewValue(v: Any?): Any? {
        if (v == null) return null
        return when (v) {
            is String, is Number, is Boolean -> v
            is Optional<*> -> v.orElse(null)?.let { previewValue(it) }
            is Iterable<*> -> v.take(20).map { previewValue(it) }
            is Map<*, *>   -> v.entries.take(20).associate { it.key.toString() to previewValue(it.value) }
            else -> v.toString().take(500)
        }
    }

    private fun collectMethods(cls: Class<*>): List<Method> {
        val seen = LinkedHashMap<String, Method>()
        for (c in lineage(cls)) {
            for (m in c.declaredMethods) {
                if (!Modifier.isPublic(m.modifiers)) continue
                val key = "${m.name}/${m.parameterCount}/${m.parameterTypes.joinToString { it.name }}"
                seen.putIfAbsent(key, m)
            }
        }
        return seen.values.sortedBy { it.name }
    }

    private fun lineage(cls: Class<*>): List<Class<*>> {
        val out = ArrayList<Class<*>>()
        val seen = HashSet<Class<*>>()
        fun walk(c: Class<*>?) {
            if (c == null || !seen.add(c)) return
            out.add(c)
            walk(c.superclass)
            for (i in c.interfaces) walk(i)
        }
        walk(cls)
        return out
    }

    private fun pickMethod(cls: Class<*>, name: String, args: List<Any?>, staticOnly: Boolean): Method? {
        val candidates = collectMethods(cls).filter { m ->
            m.name == name &&
            m.parameterCount == args.size &&
            (!staticOnly || Modifier.isStatic(m.modifiers))
        }
        if (candidates.isEmpty()) return null
        return candidates
            .map { m -> m to scoreMethod(m, args) }
            .filter { it.second >= 0 }                  // negative = incompatible
            .maxByOrNull { it.second }?.first
            ?: candidates.first()                        // last-resort fallback
    }

    /**
     * Higher score = better match. Negative = incompatible.
     * +3 exact runtime-class match
     * +2 assignable from arg's runtime class
     * +1 numeric-narrowing or boxing match for primitives
     *  0 null arg vs reference parameter
     * -1 incompatible
     */
    private fun scoreMethod(m: Method, args: List<Any?>): Int {
        val params = m.parameterTypes
        var total = 0
        for (i in args.indices) {
            val p = params[i]
            val a = args[i]
            total += when {
                a == null -> if (p.isPrimitive) -1 else 0
                p == a.javaClass -> 3
                p.isInstance(a)  -> 2
                p.isPrimitive    -> primitiveScore(p, a)
                else             -> -1
            }
            if (total < 0) return -1
        }
        return total
    }

    private fun primitiveScore(p: Class<*>, a: Any): Int = when (p) {
        java.lang.Integer.TYPE, java.lang.Long.TYPE, java.lang.Short.TYPE,
        java.lang.Byte.TYPE,    java.lang.Float.TYPE, java.lang.Double.TYPE ->
            if (a is Number) 1 else -1
        java.lang.Boolean.TYPE  -> if (a is Boolean) 1 else -1
        java.lang.Character.TYPE -> if (a is Char || (a is String && a.length == 1)) 1 else -1
        else -> -1
    }

    private fun coerceArgs(m: Method, args: List<Any?>): List<Any?> {
        val params = m.parameterTypes
        return args.mapIndexed { i, a ->
            val p = params[i]
            when {
                a == null -> null
                p == java.lang.Integer.TYPE || p == Int::class.javaObjectType   -> (a as Number).toInt()
                p == java.lang.Long.TYPE    || p == Long::class.javaObjectType  -> (a as Number).toLong()
                p == java.lang.Short.TYPE   || p == Short::class.javaObjectType -> (a as Number).toShort()
                p == java.lang.Byte.TYPE    || p == Byte::class.javaObjectType  -> (a as Number).toByte()
                p == java.lang.Float.TYPE   || p == Float::class.javaObjectType -> (a as Number).toFloat()
                p == java.lang.Double.TYPE  || p == Double::class.javaObjectType -> (a as Number).toDouble()
                p == java.lang.Boolean.TYPE || p == Boolean::class.javaObjectType -> (a as Boolean)
                else -> a
            }
        }
    }

    private fun wrap(value: Any?): CallResult {
        if (value == null) return CallResult(true, null, null, "null")
        return when (value) {
            is String, is Number, is Boolean -> CallResult(true, value, null, value.javaClass.name)
            else -> {
                val handle = handles.put(value)
                val preview = previewValue(value)
                CallResult(true, preview, handle, value.javaClass.name)
            }
        }
    }
}

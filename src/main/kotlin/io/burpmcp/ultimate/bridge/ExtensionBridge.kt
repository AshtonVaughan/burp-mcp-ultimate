package io.burpmcp.ultimate.bridge

import io.burpmcp.ultimate.mcp.ErrorCodes
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.McpException
import java.lang.reflect.Field
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.net.URLClassLoader
import java.util.Optional
import java.util.concurrent.ConcurrentHashMap

/**
 * Cross-extension reflection bridge.
 *
 * Burp loads every extension into its own ClassLoader so they can ship
 * conflicting dependencies safely. Montoya does NOT expose a way to call
 * into other extensions. We work around that by walking running threads
 * to discover extension ClassLoaders and then doing classloader-aware
 * reflection against them.
 *
 * Trade-offs documented in CLAUDE.md and docs/EXTENSION_BRIDGE.md:
 *  - Fragile: extension internals change between releases.
 *  - Per-extension knowledge: some require obfuscated class names.
 *  - Best-effort: methods declared "public" might still throw IllegalAccess
 *    if the JVM module system blocks reflection.
 *
 * The discover() result is cached for the bridge's lifetime; call
 * [refresh] if extensions are loaded/unloaded mid-session.
 */
class ExtensionBridge(private val handles: HandleStore) {

    data class Discovered(
        val label: String,
        val classLoader: ClassLoader,
        val jarUrls: List<String>,
        val seenClasses: List<String>,
    )

    /**
     * Class names we recognise per extension. If the user's extension version
     * hides them (Burp obfuscates package-private classes), the dynamic
     * discovery path still finds the ClassLoader; the agent can then list
     * loaded classes via [listClassesIn].
     *
     * Maintained alphabetically by extension display name.
     */
    companion object {
        val KNOWN_EXTENSION_CLASSES: Map<String, List<String>> = mapOf(
            "Active Scan++" to listOf(
                "burp.BurpExtender",
            ),
            "Autorize" to listOf(
                "io.portswigger.autorize.AutorizeExtensionLoader",
                "burp.BurpExtender",
            ),
            "Backslash Powered Scanner" to listOf(
                "burp.BurpExtender",
            ),
            "Collaborator Everywhere" to listOf(
                "burp.BurpExtender",
            ),
            "Hackvertor" to listOf(
                "burp.BurpExtender",
                "burp.parser.HackvertorExtension",
                "burp.parser.Convertors",
            ),
            "HTTP Request Smuggler" to listOf(
                "burp.BurpExtender",
            ),
            "InQL" to listOf(
                "inql.Extension",
                "burp.BurpExtender",
            ),
            "JWT Editor" to listOf(
                "com.blackberry.jwteditor.BurpExtender",
                "com.blackberry.jwteditor.utils.crypto.HmacUtils",
            ),
            "Logger++" to listOf(
                "com.nccgroup.loggerplusplus.LoggerPlusPlus",
                "com.nccgroup.loggerplusplus.logentry.LogEntry",
                "com.nccgroup.loggerplusplus.filter.parser.FilterCompiler",
            ),
            "Param Miner" to listOf(
                "burp.BurpExtender",
                "burp.ParamGuesser",
            ),
            "Turbo Intruder" to listOf(
                "burp.BurpExtender",
                "burp.Engine",
                "burp.Request",
            ),
        )

        /** Class names / class-name prefixes that are NOT extensions (filter noise). */
        private val NON_EXTENSION_PREFIXES = listOf(
            "java.", "javax.", "kotlin.", "kotlinx.",
            "sun.", "jdk.", "com.sun.",
            "burp.api.",                 // Montoya API itself
            "io.burpmcp.",               // Our own extension
            "io.burpmcp.shaded.",         // Our shaded jackson/coroutines
            "scala.", "groovy.",
            "org.junit.",
        )

        internal fun isLikelyExtensionClass(name: String): Boolean =
            NON_EXTENSION_PREFIXES.none { name.startsWith(it) }
    }

    @Volatile private var cache: List<Discovered>? = null

    fun discover(): List<Discovered> = cache ?: synchronized(this) {
        cache ?: doDiscover().also { cache = it }
    }

    fun refresh(): List<Discovered> = synchronized(this) {
        cache = null
        discover()
    }

    private fun doDiscover(): List<Discovered> {
        val ourCl = ExtensionBridge::class.java.classLoader
        val systemCl = ClassLoader.getSystemClassLoader()
        val byCl = LinkedHashMap<ClassLoader, MutableSet<String>>()

        // 1. Walk all running threads and collect their context class loaders.
        for ((thread, frames) in Thread.getAllStackTraces()) {
            val cl = thread.contextClassLoader ?: continue
            if (cl === ourCl || cl === systemCl || isAncestorOfOurs(cl, ourCl)) continue
            val classes = byCl.getOrPut(cl) { LinkedHashSet() }
            for (frame in frames) {
                val name = frame.className
                if (isLikelyExtensionClass(name)) classes.add(name)
            }
        }

        // 2. For each known extension, try every well-known class name against
        // every discovered classloader to label them. The same classloader can
        // hold multiple known classes (e.g. Logger++).
        val labelled = LinkedHashMap<ClassLoader, String>()
        for ((label, classNames) in KNOWN_EXTENSION_CLASSES) {
            for (cl in byCl.keys) {
                if (cl in labelled) continue
                if (classNames.any { canLoad(cl, it) }) {
                    labelled[cl] = label
                    classNames.filter { canLoad(cl, it) }
                        .forEach { byCl[cl]?.add(it) }
                }
            }
        }

        // 3. Build the final list. Unlabelled classloaders get an inferred name
        // from their JAR URLs.
        return byCl.entries.map { (cl, seen) ->
            val urls = jarUrlsOf(cl)
            val label = labelled[cl] ?: inferLabelFromUrls(urls) ?: cl.toString().take(80)
            Discovered(label, cl, urls, seen.sorted())
        }
    }

    private fun isAncestorOfOurs(cl: ClassLoader, ours: ClassLoader): Boolean {
        var p: ClassLoader? = ours.parent
        while (p != null) { if (p === cl) return true; p = p.parent }
        return false
    }

    private fun canLoad(cl: ClassLoader, name: String): Boolean = try {
        Class.forName(name, false, cl); true
    } catch (_: Throwable) { false }

    private fun jarUrlsOf(cl: ClassLoader): List<String> = try {
        when (cl) {
            is URLClassLoader -> cl.urLs.map { it.toString() }
            else -> {
                // Burp's custom classloaders are often URLClassLoader subclasses
                // with the URLs accessible reflectively.
                val ucpField = findFieldUpward(cl.javaClass, "ucp")
                    ?: findFieldUpward(cl.javaClass, "urls")
                ucpField?.also { it.isAccessible = true }?.get(cl)?.let { ucp ->
                    val getUrls = findMethodUpward(ucp.javaClass, "getURLs")
                    if (getUrls != null) {
                        getUrls.isAccessible = true
                        @Suppress("UNCHECKED_CAST")
                        (getUrls.invoke(ucp) as? Array<Any>)?.map { it.toString() } ?: emptyList()
                    } else emptyList()
                } ?: emptyList()
            }
        }
    } catch (_: Throwable) { emptyList() }

    private fun inferLabelFromUrls(urls: List<String>): String? = urls
        .firstOrNull { it.endsWith(".jar") }
        ?.substringAfterLast('/')
        ?.removeSuffix(".jar")

    // ---------------- Class loading + reflection ----------------

    fun resolveExtension(label: String): Discovered = discover()
        .firstOrNull { it.label.equals(label, ignoreCase = true) }
        ?: throw McpException(ErrorCodes.NOT_FOUND,
            "no loaded extension matches '$label'. Call bridge_list_extensions to see what's loaded.")

    fun loadClass(label: String, className: String): Class<*> {
        val ext = resolveExtension(label)
        return try {
            Class.forName(className, false, ext.classLoader)
        } catch (t: Throwable) {
            throw McpException(ErrorCodes.NOT_FOUND,
                "class '$className' not found in extension '$label': ${t.message}")
        }
    }

    /** List loaded class names visible from an extension's classloader (best-effort). */
    fun listClassesIn(label: String, prefix: String?, max: Int): List<String> {
        val ext = resolveExtension(label)
        val seen = LinkedHashSet<String>()
        seen.addAll(ext.seenClasses)
        // Prefix-driven probe: try common patterns under the prefix.
        if (prefix != null) {
            for (suffix in listOf("BurpExtender", "Main", "Plugin", "Extension")) {
                val candidate = "$prefix.$suffix"
                if (canLoad(ext.classLoader, candidate)) seen.add(candidate)
            }
        }
        return seen.filter { prefix == null || it.startsWith(prefix) }.take(max)
    }

    fun inspectClass(label: String, className: String): Map<String, Any?> {
        val cls = loadClass(label, className)
        return mapOf(
            "extension"     to label,
            "class"         to cls.name,
            "superclass"    to cls.superclass?.name,
            "interfaces"    to cls.interfaces.map { it.name },
            "methods"       to collectMethods(cls).map { describeMethod(it) },
            "static_methods" to collectMethods(cls).filter { Modifier.isStatic(it.modifiers) }.map { describeMethod(it) },
            "fields"        to collectFields(cls).map { describeField(it) },
            "constructors"  to cls.declaredConstructors.map { c ->
                mapOf(
                    "params" to c.parameterTypes.map { it.name },
                    "modifiers" to Modifier.toString(c.modifiers),
                )
            },
        )
    }

    fun invokeStatic(label: String, qualifiedName: String, rawArgs: List<Any?>): Result {
        val ext = resolveExtension(label)
        val dot = qualifiedName.lastIndexOf('.')
        require(dot > 0) { "static spec must be fully-qualified: $qualifiedName" }
        val cls = Class.forName(qualifiedName.substring(0, dot), false, ext.classLoader)
        val methodName = qualifiedName.substring(dot + 1)
        val args = rawArgs.map { resolveArg(it) }
        val m = pickMethod(cls, methodName, args, staticOnly = true)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS,
                "no static $methodName matching ${args.size} args on ${cls.name}")
        m.isAccessible = true
        val result = m.invoke(null, *coerceArgs(m, args).toTypedArray())
        return wrap(result)
    }

    fun invokeInstance(handleId: String, methodName: String, rawArgs: List<Any?>): Result {
        val target = handles.get(handleId)
            ?: throw McpException(ErrorCodes.NOT_FOUND, "no such handle: $handleId")
        val args = rawArgs.map { resolveArg(it) }
        val m = pickMethod(target.javaClass, methodName, args, staticOnly = false)
            ?: throw McpException(ErrorCodes.INVALID_PARAMS,
                "no method $methodName matching ${args.size} args on ${target.javaClass.name}")
        m.isAccessible = true
        val result = m.invoke(target, *coerceArgs(m, args).toTypedArray())
        return wrap(result)
    }

    fun construct(label: String, className: String, rawArgs: List<Any?>): Result {
        val cls = loadClass(label, className)
        val args = rawArgs.map { resolveArg(it) }
        val ctor = cls.declaredConstructors.firstOrNull { c ->
            c.parameterCount == args.size && argsAssignable(c.parameterTypes, args)
        } ?: throw McpException(ErrorCodes.INVALID_PARAMS,
            "no constructor matching ${args.size} args on ${cls.name}")
        ctor.isAccessible = true
        return wrap(ctor.newInstance(*coerceArgs(ctor.parameterTypes, args).toTypedArray()))
    }

    fun getInstanceField(handleId: String, fieldName: String): Result {
        val target = handles.get(handleId)
            ?: throw McpException(ErrorCodes.NOT_FOUND, "no such handle: $handleId")
        val f = findFieldUpward(target.javaClass, fieldName)
            ?: throw McpException(ErrorCodes.NOT_FOUND,
                "no field '$fieldName' on ${target.javaClass.name}")
        f.isAccessible = true
        return wrap(f.get(target))
    }

    fun setInstanceField(handleId: String, fieldName: String, rawValue: Any?): Result {
        val target = handles.get(handleId)
            ?: throw McpException(ErrorCodes.NOT_FOUND, "no such handle: $handleId")
        val f = findFieldUpward(target.javaClass, fieldName)
            ?: throw McpException(ErrorCodes.NOT_FOUND,
                "no field '$fieldName' on ${target.javaClass.name}")
        f.isAccessible = true
        f.set(target, coerceArg(f.type, resolveArg(rawValue)))
        return wrap(f.get(target))
    }

    fun getStaticField(label: String, qualifiedName: String): Result {
        val ext = resolveExtension(label)
        val dot = qualifiedName.lastIndexOf('.')
        require(dot > 0) { "static field spec must be fully-qualified: $qualifiedName" }
        val cls = Class.forName(qualifiedName.substring(0, dot), false, ext.classLoader)
        val name = qualifiedName.substring(dot + 1)
        val f = findFieldUpward(cls, name)
            ?: throw McpException(ErrorCodes.NOT_FOUND,
                "no static field '$name' on ${cls.name}")
        f.isAccessible = true
        return wrap(f.get(null))
    }

    // ---------------- Reflection helpers (mirrored from Reflect.kt) ----------------

    data class Result(
        val ok: Boolean,
        val value: Any?,
        val handle: String?,
        val type: String,
    )

    fun resolveArg(spec: Any?): Any? {
        if (spec == null) return null
        if (spec is Map<*, *>) {
            (spec["\$handle"] as? String)?.let { return handles.get(it) }
            (spec["\$enum"] as? String)?.let { return parseEnum(it) }
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

    internal fun pickMethod(cls: Class<*>, name: String, args: List<Any?>, staticOnly: Boolean): Method? {
        val candidates = collectMethods(cls).filter { m ->
            m.name == name &&
            m.parameterCount == args.size &&
            (!staticOnly || Modifier.isStatic(m.modifiers))
        }
        if (candidates.isEmpty()) return null
        return candidates
            .map { m -> m to scoreMethod(m, args) }
            .filter { it.second >= 0 }
            .maxByOrNull { it.second }?.first
            ?: candidates.first()
    }

    internal fun scoreMethod(m: Method, args: List<Any?>): Int {
        val params = m.parameterTypes
        var total = 0
        for (i in args.indices) {
            val p = params[i]; val a = args[i]
            total += when {
                a == null -> if (p.isPrimitive) -1 else 0
                p == a.javaClass -> 3
                p.isInstance(a) -> 2
                p.isPrimitive -> primitiveScore(p, a)
                else -> -1
            }
            if (total < 0) return -1
        }
        return total
    }

    private fun primitiveScore(p: Class<*>, a: Any): Int = when (p) {
        java.lang.Integer.TYPE, java.lang.Long.TYPE, java.lang.Short.TYPE,
        java.lang.Byte.TYPE, java.lang.Float.TYPE, java.lang.Double.TYPE ->
            if (a is Number) 1 else -1
        java.lang.Boolean.TYPE -> if (a is Boolean) 1 else -1
        java.lang.Character.TYPE -> if (a is Char || (a is String && a.length == 1)) 1 else -1
        else -> -1
    }

    private fun coerceArg(p: Class<*>, a: Any?): Any? = when {
        a == null -> null
        p == java.lang.Integer.TYPE || p == Int::class.javaObjectType -> (a as Number).toInt()
        p == java.lang.Long.TYPE || p == Long::class.javaObjectType -> (a as Number).toLong()
        p == java.lang.Short.TYPE || p == Short::class.javaObjectType -> (a as Number).toShort()
        p == java.lang.Byte.TYPE || p == Byte::class.javaObjectType -> (a as Number).toByte()
        p == java.lang.Float.TYPE || p == Float::class.javaObjectType -> (a as Number).toFloat()
        p == java.lang.Double.TYPE || p == Double::class.javaObjectType -> (a as Number).toDouble()
        p == java.lang.Boolean.TYPE || p == Boolean::class.javaObjectType -> (a as Boolean)
        else -> a
    }

    private fun coerceArgs(m: Method, args: List<Any?>): List<Any?> =
        args.mapIndexed { i, a -> coerceArg(m.parameterTypes[i], a) }

    private fun coerceArgs(params: Array<Class<*>>, args: List<Any?>): List<Any?> =
        args.mapIndexed { i, a -> coerceArg(params[i], a) }

    private fun argsAssignable(params: Array<Class<*>>, args: List<Any?>): Boolean {
        if (params.size != args.size) return false
        for (i in params.indices) {
            val p = params[i]; val a = args[i]
            if (a == null) { if (p.isPrimitive) return false; continue }
            if (p.isInstance(a)) continue
            if (p.isPrimitive && primitiveScore(p, a) >= 0) continue
            return false
        }
        return true
    }

    internal fun collectMethods(cls: Class<*>): List<Method> {
        val seen = LinkedHashMap<String, Method>()
        for (c in lineage(cls)) {
            for (m in c.declaredMethods) {
                val key = "${m.name}/${m.parameterCount}/${m.parameterTypes.joinToString { it.name }}"
                seen.putIfAbsent(key, m)
            }
        }
        return seen.values.sortedBy { it.name }
    }

    private fun collectFields(cls: Class<*>): List<Field> {
        val seen = LinkedHashMap<String, Field>()
        for (c in lineage(cls)) {
            for (f in c.declaredFields) {
                seen.putIfAbsent(f.name, f)
            }
        }
        return seen.values.sortedBy { it.name }
    }

    private fun findMethodUpward(cls: Class<*>, name: String): Method? {
        for (c in lineage(cls)) {
            for (m in c.declaredMethods) if (m.name == name) return m
        }
        return null
    }

    private fun findFieldUpward(cls: Class<*>, name: String): Field? {
        for (c in lineage(cls)) {
            for (f in c.declaredFields) if (f.name == name) return f
        }
        return null
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

    private fun describeMethod(m: Method) = mapOf(
        "name"        to m.name,
        "return_type" to m.returnType.name,
        "params"      to m.parameterTypes.map { it.name },
        "static"      to Modifier.isStatic(m.modifiers),
        "modifiers"   to Modifier.toString(m.modifiers),
    )

    private fun describeField(f: Field) = mapOf(
        "name"      to f.name,
        "type"      to f.type.name,
        "static"    to Modifier.isStatic(f.modifiers),
        "modifiers" to Modifier.toString(f.modifiers),
    )

    private fun previewValue(v: Any?, depth: Int = 0): Any? {
        if (v == null) return null
        if (depth > 3) return v.toString().take(200)
        return when (v) {
            is String, is Number, is Boolean -> v
            is Optional<*> -> v.orElse(null)?.let { previewValue(it, depth + 1) }
            is Iterable<*> -> v.take(20).map { previewValue(it, depth + 1) }
            is Map<*, *> -> v.entries.take(20).associate { it.key.toString() to previewValue(it.value, depth + 1) }
            else -> v.toString().take(500)
        }
    }

    private fun wrap(value: Any?): Result {
        if (value == null) return Result(true, null, null, "null")
        return when (value) {
            is String, is Number, is Boolean -> Result(true, value, null, value.javaClass.name)
            else -> {
                val handle = handles.put(value)
                Result(true, previewValue(value), handle, value.javaClass.name)
            }
        }
    }
}

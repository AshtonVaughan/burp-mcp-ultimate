package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Set notes / highlight colours on captured items so a human reviewer can
 * see exactly what the agent looked at and what it concluded.
 */
object AnnotationTools {

    private val COLORS = HighlightColor.values().map { it.name }

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "annotation_set",
            description = "Set notes and/or highlight colour on a handle that has annotations() (ProxyHttpRequestResponse, HttpRequestResponse, AuditIssue, etc.).",
            inputSchema = S.obj(
                properties = mapOf(
                    "handle"    to S.str("Handle id"),
                    "notes"     to S.str("Note text (omit to leave unchanged)"),
                    "highlight" to S.enum("Highlight colour", COLORS),
                ),
                required = listOf("handle"),
            ),
        ) { args ->
            val obj = handles.get(Args.str(args, "handle")) ?: error("unknown handle")
            val anns = obj.javaClass.methods.firstOrNull { it.name == "annotations" && it.parameterCount == 0 }
                ?.invoke(obj) as? Annotations
                ?: error("handle has no annotations()")

            Args.strOrNull(args, "notes")?.let { anns.setNotes(it) }
            Args.strOrNull(args, "highlight")?.let { anns.setHighlightColor(HighlightColor.valueOf(it)) }

            mapOf(
                "notes"     to anns.notes(),
                "highlight" to anns.highlightColor().name,
            )
        }

        reg.register(
            name = "annotation_get",
            description = "Read notes + highlight from a handle.",
            inputSchema = S.obj(
                properties = mapOf("handle" to S.str("Handle id")),
                required = listOf("handle"),
            ),
        ) { args ->
            val obj = handles.get(Args.str(args, "handle")) ?: error("unknown handle")
            val anns = obj.javaClass.methods.firstOrNull { it.name == "annotations" && it.parameterCount == 0 }
                ?.invoke(obj) as? Annotations
                ?: error("handle has no annotations()")
            mapOf(
                "notes"     to anns.notes(),
                "highlight" to anns.highlightColor().name,
            )
        }
    }
}

package io.burpmcp.ultimate.mcp

import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse
import java.time.Instant
import java.util.concurrent.atomic.AtomicReference

/**
 * Holds a reference to the MessageEditor that the user most recently
 * right-clicked on. This is what powers the editor_get/set tools.
 *
 * MessageEditor cannot be obtained outside the context-menu callback
 * frame; once the user picks "Send to AI" we capture the reference and
 * keep it. Editor tools work against this slot.
 */
class EditorRegistry(private val staleSeconds: Long = 600) {

    data class Slot(val editor: MessageEditorHttpRequestResponse,
                    val capturedAt: Instant,
                    val context: String)

    private val current = AtomicReference<Slot?>()

    fun set(editor: MessageEditorHttpRequestResponse, context: String) {
        current.set(Slot(editor, Instant.now(), context))
    }

    fun get(): Slot? = current.get()?.takeIf { !isStale(it) }

    fun isStale(): Boolean = current.get()?.let { isStale(it) } ?: false
    fun isStale(s: Slot): Boolean =
        s.capturedAt.plusSeconds(staleSeconds).isBefore(Instant.now())

    fun ageSeconds(): Long? = current.get()?.let {
        java.time.Duration.between(it.capturedAt, Instant.now()).seconds
    }

    fun staleSeconds(): Long = staleSeconds

    fun clear() = current.set(null)

    fun describe(): Map<String, Any?> {
        val s = current.get() ?: return mapOf("captured" to false)
        val rr = s.editor.requestResponse()
        return mapOf(
            "captured"      to true,
            "captured_at"   to s.capturedAt.toString(),
            "age_seconds"   to ageSeconds(),
            "stale"         to isStale(s),
            "stale_after_s" to staleSeconds,
            "context"       to s.context,
            "selection"     to s.editor.selectionContext().name,
            "caret"         to s.editor.caretPosition(),
            "url"           to (rr.request()?.url() ?: ""),
            "method"        to (rr.request()?.method() ?: ""),
            "has_response"  to (rr.response() != null),
        )
    }
}

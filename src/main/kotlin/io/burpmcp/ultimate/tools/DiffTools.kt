package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Programmatic diff. Burp's UI Comparer is human-only; this gives the
 * agent JSON-readable line + word diffs essential for IDOR/race work.
 *
 * Algorithm: word-level Myers diff via classical LCS dynamic programming.
 * Capped at 10000 tokens per side; clip and warn beyond that.
 */
object DiffTools {

    private fun textOf(obj: Any?): String = when (obj) {
        is String              -> obj
        is HttpResponse        -> obj.toString()
        is HttpRequest         -> obj.toString()
        is HttpRequestResponse -> "${obj.request()}\n--- response ---\n${obj.response()}"
        else -> obj?.toString() ?: ""
    }

    private data class Hunk(val tag: String, val tokens: List<String>)

    private fun diffTokens(a: List<String>, b: List<String>, maxTokens: Int): List<Hunk> {
        if (a.size > maxTokens || b.size > maxTokens) {
            return listOf(Hunk("warn", listOf("input exceeds $maxTokens tokens; clipped")))
        }
        // LCS DP table
        val dp = Array(a.size + 1) { IntArray(b.size + 1) }
        for (i in a.indices) for (j in b.indices)
            dp[i + 1][j + 1] = if (a[i] == b[j]) dp[i][j] + 1
                               else maxOf(dp[i][j + 1], dp[i + 1][j])
        // Walk back collecting hunks
        val out = ArrayDeque<Hunk>()
        var i = a.size; var j = b.size
        var curTag = ""; var curTok = ArrayDeque<String>()
        fun flush() {
            if (curTok.isNotEmpty()) {
                out.addFirst(Hunk(curTag, curTok.toList()))
                curTok.clear()
            }
        }
        while (i > 0 && j > 0) {
            when {
                a[i - 1] == b[j - 1] -> {
                    if (curTag != "eq") { flush(); curTag = "eq" }
                    curTok.addFirst(a[--i]); j--
                }
                dp[i][j - 1] >= dp[i - 1][j] -> {
                    if (curTag != "ins") { flush(); curTag = "ins" }
                    curTok.addFirst(b[--j])
                }
                else -> {
                    if (curTag != "del") { flush(); curTag = "del" }
                    curTok.addFirst(a[--i])
                }
            }
        }
        while (i > 0) {
            if (curTag != "del") { flush(); curTag = "del" }
            curTok.addFirst(a[--i])
        }
        while (j > 0) {
            if (curTag != "ins") { flush(); curTag = "ins" }
            curTok.addFirst(b[--j])
        }
        flush()
        return out.toList()
    }

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "diff_text",
            description = "Word-level diff between two text strings. Returns a list of hunks tagged 'eq' / 'ins' / 'del'.",
            inputSchema = S.obj(
                properties = mapOf(
                    "a"           to S.str("Left text"),
                    "b"           to S.str("Right text"),
                    "max_tokens"  to S.int("Per-side cap", default = 10000),
                ),
                required = listOf("a", "b"),
            ),
        ) { args ->
            val a = Args.str(args, "a").split(Regex("(?<=\\s)|(?=\\s)"))
            val b = Args.str(args, "b").split(Regex("(?<=\\s)|(?=\\s)"))
            val max = Args.int(args, "max_tokens", 10000)
            val hunks = diffTokens(a, b, max)
            mapOf(
                "hunks"  to hunks.map { mapOf("tag" to it.tag, "tokens" to it.tokens.size, "text" to it.tokens.joinToString("").take(2000)) },
                "stats"  to mapOf(
                    "ins_tokens" to hunks.filter { it.tag == "ins" }.sumOf { it.tokens.size },
                    "del_tokens" to hunks.filter { it.tag == "del" }.sumOf { it.tokens.size },
                    "eq_tokens"  to hunks.filter { it.tag == "eq"  }.sumOf { it.tokens.size },
                ),
            )
        }

        reg.register(
            name = "diff_responses",
            description = "Diff two captured items referenced by handle id (e.g. 'h7'). " +
                "Each handle must point to an HttpResponse, HttpRequest, or HttpRequestResponse. " +
                "For diffing raw strings use diff_text instead.",
            inputSchema = S.obj(
                properties = mapOf(
                    "a"          to S.str("Handle id A (e.g. 'h7')"),
                    "b"          to S.str("Handle id B (e.g. 'h8')"),
                    "max_tokens" to S.int("Per-side cap", default = 10000),
                ),
                required = listOf("a", "b"),
            ),
        ) { args ->
            val aId = Args.str(args, "a")
            val bId = Args.str(args, "b")
            val ah = handles.get(aId)
                ?: throw io.burpmcp.ultimate.mcp.McpException(
                    io.burpmcp.ultimate.mcp.ErrorCodes.NOT_FOUND,
                    "no such handle: '$aId'. Use diff_text for raw strings.")
            val bh = handles.get(bId)
                ?: throw io.burpmcp.ultimate.mcp.McpException(
                    io.burpmcp.ultimate.mcp.ErrorCodes.NOT_FOUND,
                    "no such handle: '$bId'. Use diff_text for raw strings.")
            val max = Args.int(args, "max_tokens", 10000)
            val a = textOf(ah).split(Regex("(?<=\\s)|(?=\\s)"))
            val b = textOf(bh).split(Regex("(?<=\\s)|(?=\\s)"))
            val hunks = diffTokens(a, b, max)
            mapOf(
                "left_class"  to ah.javaClass.name,
                "right_class" to bh.javaClass.name,
                "hunks"       to hunks.map { mapOf("tag" to it.tag, "tokens" to it.tokens.size, "text" to it.tokens.joinToString("").take(2000)) },
                "stats"       to mapOf(
                    "ins_tokens" to hunks.filter { it.tag == "ins" }.sumOf { it.tokens.size },
                    "del_tokens" to hunks.filter { it.tag == "del" }.sumOf { it.tokens.size },
                    "eq_tokens"  to hunks.filter { it.tag == "eq"  }.sumOf { it.tokens.size },
                ),
            )
        }
    }
}

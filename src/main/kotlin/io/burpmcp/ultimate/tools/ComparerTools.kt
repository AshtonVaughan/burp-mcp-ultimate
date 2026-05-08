package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray.byteArray
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object ComparerTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "comparer_send",
            description = "Send one or more strings to Burp's Comparer tool.",
            inputSchema = S.obj(
                properties = mapOf(
                    "items" to S.arr("Items to compare", S.str("text")),
                ),
                required = listOf("items"),
            ),
        ) { args ->
            val items = Args.listOrEmpty(args, "items").map { it.toString() }
            val arrs  = items.map { byteArray(it) }.toTypedArray()
            api.comparer().sendToComparer(*arrs)
            mapOf("ok" to true, "count" to items.size)
        }
    }
}

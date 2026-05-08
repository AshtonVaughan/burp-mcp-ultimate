package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray.byteArray
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object DecoderTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "decoder_send",
            description = "Send a string to Burp's Decoder tool.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Text to decode")),
                required = listOf("input"),
            ),
        ) { args ->
            api.decoder().sendToDecoder(byteArray(Args.str(args, "input")))
            mapOf("ok" to true)
        }
    }
}

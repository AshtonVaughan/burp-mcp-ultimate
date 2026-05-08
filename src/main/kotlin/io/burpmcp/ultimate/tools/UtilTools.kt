package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S
import java.security.MessageDigest
import java.util.Base64

object UtilTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "util_url_encode",
            description = "URL-encode a string (form-style by default).",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Plain text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().urlUtils().encode(Args.str(args, "input"))) }

        reg.register(
            name = "util_url_decode",
            description = "URL-decode a string.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Encoded text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().urlUtils().decode(Args.str(args, "input"))) }

        reg.register(
            name = "util_base64_encode",
            description = "Base64-encode a string (UTF-8).",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Plain text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().base64Utils().encodeToString(Args.str(args, "input"))) }

        reg.register(
            name = "util_base64_decode",
            description = "Base64-decode a string into UTF-8.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Base64 text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().base64Utils().decode(Args.str(args, "input")).toString()) }

        reg.register(
            name = "util_html_encode",
            description = "HTML-encode a string.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Plain text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().htmlUtils().encode(Args.str(args, "input"))) }

        reg.register(
            name = "util_html_decode",
            description = "HTML-decode a string.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Encoded text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().htmlUtils().decode(Args.str(args, "input"))) }

        reg.register(
            name = "util_random_string",
            description = "Generate a cryptographically random string.",
            inputSchema = S.obj(
                properties = mapOf(
                    "length" to S.int("Length", default = 16),
                    "alphabet" to S.enum("Charset", listOf("alnum", "alpha", "hex", "ascii"), default = "alnum"),
                ),
            ),
        ) { args ->
            val length = Args.int(args, "length", 16)
            val pool = when (Args.strOrNull(args, "alphabet") ?: "alnum") {
                "alpha" -> ('a'..'z') + ('A'..'Z')
                "hex"   -> ('0'..'9') + ('a'..'f')
                "ascii" -> (33..126).map { it.toChar() }
                else    -> ('a'..'z') + ('A'..'Z') + ('0'..'9')
            }
            val rnd = java.security.SecureRandom()
            val out = String(CharArray(length) { pool[rnd.nextInt(pool.size)] })
            mapOf("output" to out)
        }

        reg.register(
            name = "util_hash",
            description = "Hash a string with the given algorithm.",
            inputSchema = S.obj(
                properties = mapOf(
                    "input" to S.str("Plain text"),
                    "algo"  to S.enum("Algorithm",
                        listOf("md5", "sha1", "sha256", "sha384", "sha512"), default = "sha256"),
                ),
                required = listOf("input"),
            ),
        ) { args ->
            val input = Args.str(args, "input").toByteArray(Charsets.UTF_8)
            val algo = (Args.strOrNull(args, "algo") ?: "sha256").let {
                when (it) { "md5" -> "MD5"; "sha1" -> "SHA-1"; "sha256" -> "SHA-256"
                    "sha384" -> "SHA-384"; "sha512" -> "SHA-512"; else -> "SHA-256" }
            }
            val digest = MessageDigest.getInstance(algo).digest(input)
            mapOf(
                "hex"    to digest.joinToString("") { "%02x".format(it) },
                "base64" to Base64.getEncoder().encodeToString(digest),
            )
        }

        reg.register(
            name = "util_jwt_decode",
            description = "Decode a JWT into header, payload and signature parts (no verification).",
            inputSchema = S.obj(
                properties = mapOf("token" to S.str("JWT")),
                required = listOf("token"),
            ),
        ) { args ->
            val token = Args.str(args, "token").trim()
            val parts = token.split(".")
            require(parts.size == 3) { "JWT must have 3 dot-separated parts" }
            val dec = Base64.getUrlDecoder()
            mapOf(
                "header"    to String(dec.decode(parts[0])),
                "payload"   to String(dec.decode(parts[1])),
                "signature" to parts[2],
            )
        }
    }
}

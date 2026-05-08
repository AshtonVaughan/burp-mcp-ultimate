package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.ByteArray.byteArray
import burp.api.montoya.utilities.CompressionType
import burp.api.montoya.utilities.DigestAlgorithm
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/** Extra Utilities surfaces: byte/compression/crypto/json/number/string. */
object UtilExtTools {
    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "util_compress",
            description = "Compress a string with gzip/deflate/brotli.",
            inputSchema = S.obj(
                properties = mapOf(
                    "input" to S.str("Plain text"),
                    "type"  to S.enum("Compression type", listOf("GZIP", "DEFLATE", "BROTLI"), default = "GZIP"),
                ),
                required = listOf("input"),
            ),
        ) { args ->
            val type = CompressionType.valueOf(Args.strOrNull(args, "type") ?: "GZIP")
            val out  = api.utilities().compressionUtils().compress(byteArray(Args.str(args, "input")), type)
            mapOf("hex" to out.getBytes().joinToString("") { "%02x".format(it) }, "length" to out.length())
        }

        reg.register(
            name = "util_decompress",
            description = "Decompress hex-encoded bytes with gzip/deflate/brotli.",
            inputSchema = S.obj(
                properties = mapOf(
                    "hex"  to S.str("Hex-encoded compressed bytes"),
                    "type" to S.enum("Compression type", listOf("GZIP", "DEFLATE", "BROTLI"), default = "GZIP"),
                ),
                required = listOf("hex"),
            ),
        ) { args ->
            val type = CompressionType.valueOf(Args.strOrNull(args, "type") ?: "GZIP")
            val hex  = Args.str(args, "hex").replace(" ", "")
            val raw  = ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
            val out  = api.utilities().compressionUtils().decompress(byteArray(*raw), type)
            mapOf("text" to out.toString(), "length" to out.length())
        }

        reg.register(
            name = "util_digest_burp",
            description = "Generate a digest using Burp's CryptoUtils.",
            inputSchema = S.obj(
                properties = mapOf(
                    "input" to S.str("Plain text"),
                    "algo"  to S.enum("Digest algorithm",
                        listOf("MD2", "MD5", "SHA1", "SHA256", "SHA384", "SHA512"), default = "SHA256"),
                ),
                required = listOf("input"),
            ),
        ) { args ->
            val algo = DigestAlgorithm.valueOf(Args.strOrNull(args, "algo") ?: "SHA256")
            val out  = api.utilities().cryptoUtils().generateDigest(byteArray(Args.str(args, "input")), algo)
            mapOf("hex" to out.getBytes().joinToString("") { "%02x".format(it) })
        }

        reg.register(
            name = "json_read",
            description = "Read a value from a JSON document by JSON Pointer path.",
            inputSchema = S.obj(
                properties = mapOf(
                    "json" to S.str("JSON document"),
                    "path" to S.str("JSON pointer or path"),
                ),
                required = listOf("json", "path"),
            ),
        ) { args -> mapOf("value" to api.utilities().jsonUtils().read(Args.str(args, "json"), Args.str(args, "path"))) }

        reg.register(
            name = "json_update",
            description = "Update a value in a JSON document.",
            inputSchema = S.obj(
                properties = mapOf(
                    "json"  to S.str("JSON document"),
                    "path"  to S.str("JSON pointer"),
                    "value" to S.str("New value (string)"),
                ),
                required = listOf("json", "path", "value"),
            ),
        ) { args ->
            mapOf("result" to api.utilities().jsonUtils().update(
                Args.str(args, "json"), Args.str(args, "path"), Args.str(args, "value")))
        }

        reg.register(
            name = "json_add",
            description = "Add a value to a JSON document at a path.",
            inputSchema = S.obj(
                properties = mapOf(
                    "json"  to S.str("JSON document"),
                    "path"  to S.str("JSON pointer"),
                    "value" to S.str("Value"),
                ),
                required = listOf("json", "path", "value"),
            ),
        ) { args ->
            mapOf("result" to api.utilities().jsonUtils().add(
                Args.str(args, "json"), Args.str(args, "path"), Args.str(args, "value")))
        }

        reg.register(
            name = "json_remove",
            description = "Remove a value from a JSON document at a path.",
            inputSchema = S.obj(
                properties = mapOf(
                    "json" to S.str("JSON document"),
                    "path" to S.str("JSON pointer"),
                ),
                required = listOf("json", "path"),
            ),
        ) { args ->
            mapOf("result" to api.utilities().jsonUtils().remove(Args.str(args, "json"), Args.str(args, "path")))
        }

        reg.register(
            name = "json_is_valid",
            description = "Check if a string is valid JSON.",
            inputSchema = S.obj(
                properties = mapOf("json" to S.str("Possibly-JSON text")),
                required = listOf("json"),
            ),
        ) { args -> mapOf("valid" to api.utilities().jsonUtils().isValidJson(Args.str(args, "json"))) }

        reg.register(
            name = "number_convert",
            description = "Convert between binary, octal, decimal and hex.",
            inputSchema = S.obj(
                properties = mapOf(
                    "input" to S.str("Number as string"),
                    "from"  to S.enum("Source base", listOf("binary", "octal", "decimal", "hex")),
                    "to"    to S.enum("Target base", listOf("binary", "octal", "decimal", "hex")),
                ),
                required = listOf("input", "from", "to"),
            ),
        ) { args ->
            val n = api.utilities().numberUtils()
            val input = Args.str(args, "input")
            val from = Args.str(args, "from")
            val to = Args.str(args, "to")
            val out = when ("$from->$to") {
                "binary->octal"   -> n.convertBinaryToOctal(input)
                "binary->decimal" -> n.convertBinaryToDecimal(input)
                "binary->hex"     -> n.convertBinaryToHex(input)
                "octal->binary"   -> n.convertOctalToBinary(input)
                "octal->decimal"  -> n.convertOctalToDecimal(input)
                "octal->hex"      -> n.convertOctalToHex(input)
                "decimal->binary" -> n.convertDecimalToBinary(input)
                "decimal->octal"  -> n.convertDecimalToOctal(input)
                "decimal->hex"    -> n.convertDecimalToHex(input)
                "hex->binary"     -> n.convertHexToBinary(input)
                "hex->octal"      -> n.convertHexToOctal(input)
                "hex->decimal"    -> n.convertHexToDecimal(input)
                else -> error("unknown conversion $from->$to")
            }
            mapOf("output" to out)
        }

        reg.register(
            name = "ascii_to_hex",
            description = "Convert ASCII string to hex.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("ASCII text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().stringUtils().convertAsciiToHexString(Args.str(args, "input"))) }

        reg.register(
            name = "hex_to_ascii",
            description = "Convert hex string to ASCII.",
            inputSchema = S.obj(
                properties = mapOf("input" to S.str("Hex text")),
                required = listOf("input"),
            ),
        ) { args -> mapOf("output" to api.utilities().stringUtils().convertHexStringToAscii(Args.str(args, "input"))) }
    }
}

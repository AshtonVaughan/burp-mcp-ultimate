package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.Json
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.net.URLEncoder

object OAuthTools {

    private fun get(api: MontoyaApi, url: String): String {
        val u = java.net.URI(url)
        val secure = u.scheme.equals("https", ignoreCase = true)
        val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
        val path = u.rawPath.ifEmpty { "/" } + (if (u.rawQuery != null) "?${u.rawQuery}" else "")
        val raw = "GET $path HTTP/1.1\r\nHost: ${u.host}\r\nAccept: application/json\r\n\r\n"
        val req = HttpRequest.httpRequest(HttpService.httpService(u.host, port, secure), raw)
        val rr = api.http().sendRequest(req, HttpMode.AUTO)
        return rr.response().bodyToString()
    }

    private fun post(api: MontoyaApi, url: String, body: String,
                     contentType: String = "application/x-www-form-urlencoded"): String {
        val u = java.net.URI(url)
        val secure = u.scheme.equals("https", ignoreCase = true)
        val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
        val path = u.rawPath.ifEmpty { "/" }
        val raw = """POST $path HTTP/1.1
Host: ${u.host}
Content-Type: $contentType
Content-Length: ${body.toByteArray().size}
Accept: application/json

$body"""
        val req = HttpRequest.httpRequest(HttpService.httpService(u.host, port, secure), raw)
        return api.http().sendRequest(req, HttpMode.AUTO).response().bodyToString()
    }

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "oidc_discover",
            description = "Fetch /.well-known/openid-configuration for an issuer and return the parsed JSON.",
            inputSchema = S.obj(
                properties = mapOf("issuer" to S.str("Issuer URL (no trailing /.well-known)")),
                required = listOf("issuer"),
            ),
        ) { args ->
            val issuer = Args.str(args, "issuer").trimEnd('/')
            val body = get(api, "$issuer/.well-known/openid-configuration")
            try {
                @Suppress("UNCHECKED_CAST")
                val cfg = Json.mapper.readValue(body, Map::class.java) as Map<String, Any?>
                cfg
            } catch (_: Throwable) {
                mapOf("raw_body" to body)
            }
        }

        reg.register(
            name = "oauth_decode_access_token",
            description = "Decode an opaque-or-JWT OAuth access token. JWT parts are base64url-decoded; opaque tokens are returned as-is.",
            inputSchema = S.obj(
                properties = mapOf("token" to S.str("Access token")),
                required = listOf("token"),
            ),
        ) { args ->
            val token = Args.str(args, "token").trim()
            val parts = token.split(".")
            if (parts.size != 3) {
                mapOf("kind" to "opaque", "token" to token, "length" to token.length)
            } else {
                val dec = Base64.getUrlDecoder()
                mapOf(
                    "kind"      to "jwt",
                    "header"    to String(dec.decode(parts[0])),
                    "payload"   to String(dec.decode(parts[1])),
                    "signature" to parts[2],
                    "alg"       to Regex("\"alg\"\\s*:\\s*\"([^\"]+)\"").find(String(dec.decode(parts[0])))?.groupValues?.get(1),
                )
            }
        }

        reg.register(
            name = "oauth_build_pkce",
            description = "Generate a PKCE verifier + S256 challenge.",
            inputSchema = S.obj(
                properties = mapOf("verifier_length" to S.int("Length 43-128", default = 64)),
            ),
        ) { args ->
            val len = Args.int(args, "verifier_length", 64).coerceIn(43, 128)
            val rnd = SecureRandom()
            val pool = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '.', '_', '~')
            val verifier = String(CharArray(len) { pool[rnd.nextInt(pool.size)] })
            val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
            val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
            mapOf(
                "code_verifier"        to verifier,
                "code_challenge"       to challenge,
                "code_challenge_method" to "S256",
            )
        }

        reg.register(
            name = "oauth_token_exchange",
            description = "POST to a token endpoint with grant_type and the usual fields.",
            inputSchema = S.obj(
                properties = mapOf(
                    "token_url"     to S.str("Token endpoint URL"),
                    "grant_type"    to S.enum("Grant type",
                        listOf("authorization_code", "refresh_token", "client_credentials", "password"),
                        default = "authorization_code"),
                    "client_id"     to S.str("client_id"),
                    "client_secret" to S.str("client_secret (optional for public clients)"),
                    "code"          to S.str("Auth code (for authorization_code)"),
                    "redirect_uri"  to S.str("Redirect URI"),
                    "code_verifier" to S.str("PKCE verifier"),
                    "refresh_token" to S.str("Refresh token (for refresh_token grant)"),
                    "username"      to S.str("Username (for password grant)"),
                    "password"      to S.str("Password (for password grant)"),
                    "scope"         to S.str("Space-delimited scopes"),
                ),
                required = listOf("token_url", "client_id"),
            ),
        ) { args ->
            val params = LinkedHashMap<String, String>()
            params["grant_type"]    = Args.strOrNull(args, "grant_type") ?: "authorization_code"
            params["client_id"]     = Args.str(args, "client_id")
            for (k in listOf("client_secret", "code", "redirect_uri", "code_verifier",
                             "refresh_token", "username", "password", "scope")) {
                Args.strOrNull(args, k)?.let { params[k] = it }
            }
            val body = params.entries.joinToString("&") {
                "${URLEncoder.encode(it.key, "UTF-8")}=${URLEncoder.encode(it.value, "UTF-8")}"
            }
            mapOf("response" to post(api, Args.str(args, "token_url"), body))
        }
    }
}

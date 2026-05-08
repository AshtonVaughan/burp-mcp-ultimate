package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Static-only analysis of JavaScript text. Patterns intentionally
 * conservative to keep noise low; agent should follow up on hits.
 */
object JsAnalysisTools {

    private val URL_PATTERNS = listOf(
        // String literal looking like a path or URL
        Regex("""["'`](https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,300})["'`]"""),
        Regex("""["'`](/(?:api|v1|v2|v3|graphql|admin|auth|login|logout|me|user[s]?|account[s]?|order[s]?|invoice[s]?|payment[s]?|file[s]?|upload[s]?|download[s]?|search|export|internal)[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{0,200})["'`]"""),
    )

    private val SECRET_PATTERNS = listOf(
        "aws_access_key"   to Regex("""AKIA[0-9A-Z]{16}"""),
        "aws_secret_key"   to Regex("""(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"""),
        "google_api_key"   to Regex("""AIza[0-9A-Za-z\-_]{35}"""),
        "github_token"     to Regex("""gh[pousr]_[A-Za-z0-9]{36,}"""),
        "slack_token"      to Regex("""xox[baprs]-[A-Za-z0-9-]{10,}"""),
        "stripe_live"      to Regex("""sk_live_[A-Za-z0-9]{20,}"""),
        "stripe_test"      to Regex("""sk_test_[A-Za-z0-9]{20,}"""),
        "private_key_pem"  to Regex("""-----BEGIN ([A-Z ]+)PRIVATE KEY-----"""),
        "jwt"              to Regex("""eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"""),
        "firebase_url"     to Regex("""https://[a-z0-9-]+\.firebaseio\.com"""),
        "azure_storage"    to Regex("""DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]+"""),
    )

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "js_extract_endpoints",
            description = "Pull URL / path string literals out of JavaScript source.",
            inputSchema = S.obj(
                properties = mapOf(
                    "source" to S.str("JS source text"),
                    "limit"  to S.int("Max endpoints", default = 200),
                ),
                required = listOf("source"),
            ),
        ) { args ->
            val src = Args.str(args, "source")
            val limit = Args.int(args, "limit", 200)
            val hits = LinkedHashSet<String>()
            for (p in URL_PATTERNS) for (m in p.findAll(src)) {
                hits += m.groupValues[1]
                if (hits.size >= limit) break
            }
            mapOf("count" to hits.size, "endpoints" to hits.toList())
        }

        reg.register(
            name = "js_scan_secrets",
            description = "Regex-scan JavaScript source for common API keys and secrets.",
            inputSchema = S.obj(
                properties = mapOf(
                    "source"      to S.str("JS source text"),
                    "limit_per"   to S.int("Max hits per pattern", default = 20),
                ),
                required = listOf("source"),
            ),
        ) { args ->
            val src = Args.str(args, "source")
            val limit = Args.int(args, "limit_per", 20)
            val findings = LinkedHashMap<String, List<String>>()
            for ((label, pattern) in SECRET_PATTERNS) {
                val matches = pattern.findAll(src).map { it.value }.distinct().take(limit).toList()
                if (matches.isNotEmpty()) findings[label] = matches
            }
            mapOf(
                "patterns_with_hits" to findings.size,
                "total_hits"         to findings.values.sumOf { it.size },
                "findings"           to findings,
            )
        }

        reg.register(
            name = "js_scan_response",
            description = "Convenience wrapper: fetches an URL with Burp's HTTP and runs both endpoint extraction and secret scan on the body.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("Full URL to a .js file or HTML page")),
                required = listOf("url"),
            ),
        ) { args ->
            val u = java.net.URI(Args.str(args, "url"))
            val secure = u.scheme.equals("https", ignoreCase = true)
            val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
            val path = u.rawPath.ifEmpty { "/" } + (if (u.rawQuery != null) "?${u.rawQuery}" else "")
            val raw = "GET $path HTTP/1.1\r\nHost: ${u.host}\r\nAccept: */*\r\n\r\n"
            val req = burp.api.montoya.http.message.requests.HttpRequest.httpRequest(
                burp.api.montoya.http.HttpService.httpService(u.host, port, secure), raw)
            val body = api.http().sendRequest(req).response().bodyToString()

            val endpoints = LinkedHashSet<String>()
            for (p in URL_PATTERNS) for (m in p.findAll(body)) {
                endpoints += m.groupValues[1]
                if (endpoints.size >= 200) break
            }
            val findings = LinkedHashMap<String, List<String>>()
            for ((label, pattern) in SECRET_PATTERNS) {
                val ms = pattern.findAll(body).map { it.value }.distinct().take(10).toList()
                if (ms.isNotEmpty()) findings[label] = ms
            }
            mapOf(
                "body_length" to body.length,
                "endpoints"   to endpoints.toList(),
                "secrets"     to findings,
            )
        }
    }
}

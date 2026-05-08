package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

/**
 * Agent-native attack tools that don't depend on third-party Burp extensions.
 *
 * These are deliberately scoped to the 80% case the agent reaches for most:
 *  - param_miner_lite : bulk header / parameter probing for reflection / behaviour deltas
 *  - bypass_403       : documented 403/401 bypass tricks
 *  - cors_misconfig_probe : permissive-CORS detection
 *
 * Each tool returns structured findings the agent can act on without us
 * needing the user to install a specific extension. The full PortSwigger
 * Param Miner remains the gold standard for human-driven sessions; these
 * tools are for the AI.
 */
object AttackTools {

    fun register(reg: ToolRegistry, api: MontoyaApi) {
        registerParamMinerLite(reg, api)
        registerBypass403(reg, api)
        registerCorsProbe(reg, api)
        registerFingerprint(reg, api)
        registerOpenRedirect(reg, api)
    }

    // ============================ fingerprint_target ============================

    private fun registerFingerprint(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "fingerprint_target",
            description = "Comprehensive first-look recon of a single host: tech stack from headers, " +
                "robots.txt + sitemap.xml + security.txt + .well-known endpoints, common admin paths, " +
                "WAF/CDN detection, default error page bodies. Single tool replaces 10+ manual http_send_raw " +
                "calls when the agent first encounters a target.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"   to S.str("Target host"),
                    "port"   to S.int("Port (default 443 if secure, else 80)"),
                    "secure" to S.bool("HTTPS", default = true),
                ),
                required = listOf("host"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val service = HttpService.httpService(host, port, secure)

            val probes = listOf(
                "GET /" to "root",
                "HEAD /" to "head_root",
                "GET /robots.txt" to "robots",
                "GET /sitemap.xml" to "sitemap",
                "GET /.well-known/security.txt" to "security_txt",
                "GET /.well-known/openid-configuration" to "oidc",
                "GET /favicon.ico" to "favicon",
                "GET /admin" to "admin",
                "GET /login" to "login",
                "GET /api" to "api_root",
                "GET /api/v1" to "api_v1",
                "GET /graphql" to "graphql",
                "GET /server-status" to "server_status",
                "GET /.git/HEAD" to "git_head",
                "GET /.env" to "dotenv",
                "GET /this-path-should-404-baseline-${System.nanoTime()}" to "baseline_404",
            )
            val results = probes.map { (line, label) ->
                val parts = line.split(" ", limit = 2)
                val method = parts[0]
                val path = parts[1]
                val raw = buildRawRequest(method, path, host, emptyList())
                val r = sendOne(api, service, raw)
                Triple(label, path, r)
            }

            // Tech-stack hints from root response.
            val rootResp = results.firstOrNull { it.first == "root" }?.third
            val techHints = mutableListOf<String>()
            if (rootResp != null) {
                rootResp.headerValue("Server")?.let { techHints += "Server: $it" }
                rootResp.headerValue("X-Powered-By")?.let { techHints += "X-Powered-By: $it" }
                rootResp.headerValue("X-AspNet-Version")?.let { techHints += "X-AspNet-Version: $it" }
                rootResp.headerValue("X-Generator")?.let { techHints += "X-Generator: $it" }
                rootResp.headerValue("Via")?.let { techHints += "Via: $it" }
                if (rootResp.headerValue("CF-Ray") != null) techHints += "WAF: Cloudflare"
                if (rootResp.headerValue("X-Akamai-Transformed") != null) techHints += "WAF: Akamai"
                if (rootResp.headerValue("X-Sucuri-ID") != null) techHints += "WAF: Sucuri"
                if (rootResp.headerValue("X-Amz-Cf-Id") != null) techHints += "CDN: AWS CloudFront"
                if (rootResp.headerValue("X-Fastly-Request-ID") != null) techHints += "CDN: Fastly"
                rootResp.headerValue("Set-Cookie")?.let { c ->
                    when {
                        c.contains("PHPSESSID", ignoreCase = true) -> techHints += "Lang: PHP"
                        c.contains("JSESSIONID", ignoreCase = true) -> techHints += "Lang: Java/J2EE"
                        c.contains("ASP.NET_SessionId", ignoreCase = true) -> techHints += "Lang: ASP.NET"
                        c.contains("connect.sid", ignoreCase = true) -> techHints += "Lang: Node.js (Express)"
                        c.contains("rack.session", ignoreCase = true) -> techHints += "Lang: Ruby (Rack)"
                        c.contains("django_session", ignoreCase = true) -> techHints += "Lang: Python (Django)"
                        c.contains("session=", ignoreCase = true) -> techHints += "Generic session cookie"
                    }
                }
                rootResp.headerValue("Content-Security-Policy")?.let { techHints += "CSP present (truncated): ${it.take(80)}" }
                if (rootResp.headerValue("Strict-Transport-Security") == null && secure) techHints += "Missing HSTS"
                if (rootResp.headerValue("X-Frame-Options") == null) techHints += "Missing X-Frame-Options"
            }

            // Discoveries: any non-404 path that 404 baseline has.
            val baseline404 = results.firstOrNull { it.first == "baseline_404" }?.third
            val discoveries = results.filter { (label, _, r) ->
                label != "baseline_404" && label != "root" && label != "head_root" &&
                r.statusCode in 200..399 &&
                (baseline404 == null || r.statusCode != baseline404.statusCode || r.bodyLength != baseline404.bodyLength)
            }.map { (label, path, r) ->
                mapOf(
                    "label"       to label,
                    "path"        to path,
                    "status_code" to r.statusCode,
                    "body_length" to r.bodyLength,
                    "content_type" to r.headerValue("Content-Type"),
                )
            }

            mapOf(
                "host"           to host,
                "port"           to port,
                "secure"         to secure,
                "root_status"    to (rootResp?.statusCode ?: 0),
                "tech_hints"     to techHints,
                "discoveries"    to discoveries,
                "baseline_404"   to (baseline404?.let { mapOf("status" to it.statusCode, "length" to it.bodyLength) }),
                "all_probes"     to results.map { (label, path, r) ->
                    mapOf("label" to label, "path" to path,
                          "status_code" to r.statusCode, "body_length" to r.bodyLength)
                },
            )
        }
    }

    // ============================ open_redirect_probe ============================

    private fun registerOpenRedirect(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "open_redirect_probe",
            description = "Test a URL parameter for open-redirect vulnerability. Sends N variants of the " +
                "attacker-controlled redirect target (canonical, double-slash, protocol-relative, whitespace " +
                "tricks, encoded variants) and reports which produce a 30x to the attacker host.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"      to S.str("Target host"),
                    "port"      to S.int("Port"),
                    "secure"    to S.bool("HTTPS", default = true),
                    "path"      to S.str("Path including the redirect parameter (e.g. /login?next=)"),
                    "param"     to S.str("Parameter name being tested (e.g. 'next', 'redirect_uri', 'returnTo')"),
                    "attacker"  to S.str("Attacker-controlled host", default = "evil.example.com"),
                ),
                required = listOf("host", "path", "param"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val basePath = Args.str(args, "path")
            val param = Args.str(args, "param")
            val attacker = Args.strOrNull(args, "attacker") ?: "evil.example.com"
            val service = HttpService.httpService(host, port, secure)

            val payloads = listOf(
                "canonical-https" to "https://$attacker",
                "canonical-http" to "http://$attacker",
                "protocol-relative" to "//$attacker",
                "backslash-trick" to "/\\$attacker",
                "double-slash" to "////$attacker",
                "whitespace-prefix" to "%20//$attacker",
                "tab-prefix" to "%09//$attacker",
                "url-encoded" to "https%3A%2F%2F$attacker",
                "double-encoded" to "https%253A%252F%252F$attacker",
                "userinfo-trick" to "https://$host@$attacker",
                "subdomain-trick" to "https://$host.$attacker",
                "javascript-scheme" to "javascript:alert(1)",
                "data-scheme" to "data:text/html,<h1>x</h1>",
            )

            val findings = mutableListOf<Map<String, Any?>>()
            for ((name, value) in payloads) {
                val sep = if (basePath.contains("?")) "&" else "?"
                val urlPath = "$basePath${sep}$param=${value.replace(" ", "%20")}"
                val raw = buildRawRequest("GET", urlPath, host, emptyList())
                val r = sendOne(api, service, raw)
                val location = r.headerValue("Location")
                val redirectsToAttacker = location != null && (
                    location.contains(attacker, ignoreCase = true) ||
                    location.contains(value, ignoreCase = true)
                )
                if (r.statusCode in 300..399 && redirectsToAttacker) {
                    findings.add(
                        mapOf(
                            "variant"      to name,
                            "payload"      to value,
                            "status_code"  to r.statusCode,
                            "location"     to location,
                            "exploitable"  to (location?.startsWith("http://$attacker", ignoreCase = true) == true ||
                                              location?.startsWith("https://$attacker", ignoreCase = true) == true ||
                                              location?.startsWith("//$attacker", ignoreCase = true) == true),
                        ),
                    )
                }
            }

            mapOf(
                "param"          to param,
                "tested_payloads" to payloads.size,
                "finding_count"  to findings.size,
                "findings"       to findings,
                "summary"        to when {
                    findings.any { it["exploitable"] == true } ->
                        "EXPLOITABLE: At least one payload produced a redirect to the attacker host. Worth ~$500-2k on most programs."
                    findings.isNotEmpty() ->
                        "Partial: Server redirects but Location header may be sanitized. Manual verification needed."
                    else ->
                        "No open redirect detected on this parameter. Consider testing other redirect-style parameters (logout_uri, callback, success_url)."
                },
            )
        }
    }

    // ============================ param_miner_lite ============================

    /** Common parameter names. Curated from SecLists + Param Miner's defaults. */
    private val DEFAULT_PARAM_WORDLIST = listOf(
        "id", "user", "user_id", "uid", "userId", "username", "email",
        "page", "p", "limit", "offset", "size", "count", "max",
        "callback", "jsonp", "redirect", "redirect_uri", "redirect_url", "url", "next", "return", "returnTo", "returnUrl", "back", "continue", "destination",
        "debug", "test", "admin", "is_admin", "isAdmin", "role", "access", "auth", "key", "token", "api_key", "apikey", "secret",
        "file", "filename", "path", "dir", "folder", "include",
        "search", "q", "query", "keyword", "term",
        "type", "kind", "format", "mode", "action", "op", "cmd",
        "sort", "order", "dir", "asc", "desc",
        "lang", "locale", "country", "region",
        "ref", "referer", "source", "from",
        "cache", "no_cache", "force",
        "preview", "draft", "hidden", "private", "public",
    )

    /** Common header names that often unlock unintended behaviour when injected. */
    private val DEFAULT_HEADER_WORDLIST = listOf(
        "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port",
        "X-Real-IP", "X-Originating-IP", "X-Remote-IP", "X-Client-IP", "X-Custom-IP-Authorization",
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL", "X-Override-Host",
        "X-Host", "X-HTTP-Host-Override", "X-Forwarded-Server",
        "X-HTTP-Method-Override", "X-Method-Override", "X-Method", "X-HTTP-Method",
        "X-Original-Host", "X-Backend-Host",
        "X-Cache", "X-Cache-Status", "X-Cache-Key",
        "X-Wap-Profile", "X-Country-Code",
        "Forwarded", "Via", "True-Client-IP",
        "X-ProxyUser-IP", "Client-IP",
        "X-Server-IP",
        "Cookie",  // probing for unkeyed cookie
        "Authorization",
        "X-CSRF-Token", "X-Requested-With",
    )

    private fun registerParamMinerLite(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "param_miner_lite",
            description = "Bulk-probe an endpoint with a wordlist of header or parameter names, comparing each " +
                "response against a baseline. Flags entries that change status code, body length, or response " +
                "headers, indicating the server is processing the injected name. Lightweight agent-native " +
                "alternative to PortSwigger's Param Miner (which is right-click-driven and unreachable from " +
                "Montoya). Probes one name per request.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"        to S.str("Target host"),
                    "port"        to S.int("Port (default 443 if secure, else 80)"),
                    "secure"      to S.bool("HTTPS", default = true),
                    "path"        to S.str("Path including query string (e.g. /api/v1/users)", default = "/"),
                    "method"      to S.enum("HTTP method", listOf("GET", "POST", "PUT", "PATCH", "OPTIONS"), default = "GET"),
                    "mode"        to S.enum("Probe target", listOf("headers", "params"), default = "headers"),
                    "marker"      to S.str("Canary value to inject (must be unlikely to occur naturally)", default = "burpmcprobe1234"),
                    "wordlist"    to S.arr("Override the default wordlist (one name per element)", S.str("name")),
                    "extra_headers" to S.arr("Additional headers to send on every request as 'Name: value'", S.str("hdr")),
                    "max"         to S.int("Cap on number of probes (after wordlist + dedup)", default = 100),
                ),
                required = listOf("host"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val path = Args.strOrNull(args, "path") ?: "/"
            val method = (Args.strOrNull(args, "method") ?: "GET").uppercase()
            val mode = Args.strOrNull(args, "mode") ?: "headers"
            val marker = Args.strOrNull(args, "marker") ?: "burpmcprobe1234"
            val max = Args.int(args, "max", 100).coerceIn(1, 500)

            @Suppress("UNCHECKED_CAST")
            val wordlist = (args["wordlist"] as? List<Any?>)?.map { it.toString() }
                ?.takeIf { it.isNotEmpty() }
                ?: when (mode) { "params" -> DEFAULT_PARAM_WORDLIST; else -> DEFAULT_HEADER_WORDLIST }

            @Suppress("UNCHECKED_CAST")
            val extraHeaders = (args["extra_headers"] as? List<Any?>)?.map { it.toString() } ?: emptyList()

            val deduped = wordlist.distinct().take(max)
            val service = HttpService.httpService(host, port, secure)

            // Build baseline raw request (no probe injection).
            val baselineRaw = buildRawRequest(method, path, host, extraHeaders)
            val baselineResp = sendOne(api, service, baselineRaw)

            val findings = mutableListOf<Map<String, Any?>>()
            for (name in deduped) {
                val raw = when (mode) {
                    "headers" -> {
                        val patched = extraHeaders.toMutableList()
                        patched.add("$name: $marker")
                        buildRawRequest(method, path, host, patched)
                    }
                    "params" -> {
                        val sep = if (path.contains("?")) "&" else "?"
                        val patchedPath = "$path${sep}$name=$marker"
                        buildRawRequest(method, patchedPath, host, extraHeaders)
                    }
                    else -> buildRawRequest(method, path, host, extraHeaders)
                }
                val r = sendOne(api, service, raw)
                val anomaly = analyzeAnomaly(baselineResp, r, marker)
                if (anomaly != null) {
                    findings.add(
                        mapOf(
                            "name"          to name,
                            "anomaly"       to anomaly.type,
                            "evidence"      to anomaly.evidence,
                            "status_code"   to r.statusCode,
                            "body_length"   to r.bodyLength,
                            "delta_length"  to (r.bodyLength - baselineResp.bodyLength),
                            "delta_status"  to (if (r.statusCode != baselineResp.statusCode) "${baselineResp.statusCode}->${r.statusCode}" else null),
                        ),
                    )
                }
            }
            mapOf(
                "mode"             to mode,
                "marker"           to marker,
                "probes_sent"      to deduped.size + 1,  // + baseline
                "baseline_status"  to baselineResp.statusCode,
                "baseline_length"  to baselineResp.bodyLength,
                "findings"         to findings,
                "finding_count"    to findings.size,
            )
        }
    }

    // ================================ bypass_403 ================================

    private fun registerBypass403(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "bypass_403",
            description = "Try the documented 403/401 bypass tricks against a forbidden URL: path encoding " +
                "(%2e, %2f, ..;/), header tricks (X-Original-URL, X-Rewrite-URL, X-Custom-IP-Authorization, " +
                "X-Forwarded-For: 127.0.0.1, etc.), method overrides, and capitalization tricks. Reports " +
                "every variant whose response is not a 4xx (or whose status differs from the baseline 403).",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"   to S.str("Target host"),
                    "port"   to S.int("Port"),
                    "secure" to S.bool("HTTPS", default = true),
                    "path"   to S.str("Forbidden path (e.g. /admin)"),
                    "method" to S.enum("Original method", listOf("GET", "POST", "PUT", "DELETE"), default = "GET"),
                    "extra_headers" to S.arr("Additional headers on every variant", S.str("hdr")),
                ),
                required = listOf("host", "path"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val path = Args.str(args, "path")
            val method = (Args.strOrNull(args, "method") ?: "GET").uppercase()

            @Suppress("UNCHECKED_CAST")
            val extra = (args["extra_headers"] as? List<Any?>)?.map { it.toString() } ?: emptyList()
            val service = HttpService.httpService(host, port, secure)

            // Baseline.
            val baselineRaw = buildRawRequest(method, path, host, extra)
            val baseline = sendOne(api, service, baselineRaw)

            data class Variant(val name: String, val raw: String)
            val variants = mutableListOf<Variant>()

            // Path-encoding tricks.
            for ((label, mutated) in pathMutations(path)) {
                variants.add(Variant("path:$label", buildRawRequest(method, mutated, host, extra)))
            }

            // Header tricks.
            for ((label, headers) in headerBypassSets(path)) {
                variants.add(Variant("header:$label", buildRawRequest(method, "/", host, extra + headers)))
            }

            // Method override.
            for (m in listOf("POST", "PUT", "OPTIONS", "TRACE", "PATCH")) {
                if (m == method) continue
                variants.add(Variant("method:$m", buildRawRequest(m, path, host, extra)))
            }

            // Method-override headers.
            for (h in listOf("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method", "X-Method")) {
                variants.add(Variant("method-override-header:$h",
                    buildRawRequest("POST", path, host, extra + listOf("$h: GET"))))
            }

            val unblocked = mutableListOf<Map<String, Any?>>()
            for (v in variants) {
                val r = sendOne(api, service, v.raw)
                val statusChanged = r.statusCode != baseline.statusCode
                val notForbidden = r.statusCode in 200..299 || r.statusCode in 300..399
                if (statusChanged || notForbidden) {
                    unblocked.add(
                        mapOf(
                            "variant"      to v.name,
                            "status_code"  to r.statusCode,
                            "body_length"  to r.bodyLength,
                            "delta_status" to "${baseline.statusCode}->${r.statusCode}",
                            "interesting"  to (if (notForbidden) "non-4xx response" else "status differs from baseline"),
                        ),
                    )
                }
            }
            mapOf(
                "baseline_status"    to baseline.statusCode,
                "baseline_length"    to baseline.bodyLength,
                "variants_tried"     to variants.size,
                "interesting_count"  to unblocked.size,
                "interesting"        to unblocked,
            )
        }
    }

    private fun pathMutations(path: String): List<Pair<String, String>> {
        val p = if (path.startsWith("/")) path else "/$path"
        val out = mutableListOf<Pair<String, String>>()
        out += "trailing-slash" to "$p/"
        out += "trailing-double-slash" to "$p//"
        out += "trailing-semicolon" to "$p;"
        out += "trailing-semicolon-slash" to "$p;/"
        out += "leading-slash-double" to "/$p"  // path becomes "//$p"
        out += "ascii-tab-prefix" to "\t$p"
        out += "case-mixed" to p.mapIndexed { i, c -> if (i % 2 == 0) c.uppercaseChar() else c }.joinToString("")
        out += "encoded-slash" to p.replace("/", "%2f", ignoreCase = false)
        out += "encoded-dot" to p.replace(".", "%2e")
        out += "double-encoded-slash" to p.replace("/", "%252f")
        out += "url-anchor" to "$p#"
        out += "url-anchor-prefix" to "$p#/admin"
        out += "ext-suffix-html" to "$p.html"
        out += "ext-suffix-json" to "$p.json"
        out += "query-anything" to "$p?anything"
        out += "dotsegment-bypass" to "/.;/$p"
        out += "dotdot-encoded" to "/..%2f${p.removePrefix("/")}"
        return out
    }

    private fun headerBypassSets(path: String): List<Pair<String, List<String>>> = listOf(
        "X-Original-URL" to listOf("X-Original-URL: $path"),
        "X-Rewrite-URL" to listOf("X-Rewrite-URL: $path"),
        "X-Override-URL" to listOf("X-Override-URL: $path"),
        "X-Custom-IP-Authorization" to listOf("X-Custom-IP-Authorization: 127.0.0.1"),
        "X-Forwarded-For-localhost" to listOf("X-Forwarded-For: 127.0.0.1"),
        "X-Real-IP-localhost" to listOf("X-Real-IP: 127.0.0.1"),
        "X-Forwarded-Host-target" to listOf("X-Forwarded-Host: localhost"),
        "X-Originating-IP" to listOf("X-Originating-IP: 127.0.0.1"),
        "X-Remote-IP" to listOf("X-Remote-IP: 127.0.0.1"),
        "X-Client-IP" to listOf("X-Client-IP: 127.0.0.1"),
        "Forwarded-localhost" to listOf("Forwarded: for=127.0.0.1;by=127.0.0.1"),
        "Referer-self" to listOf("Referer: http://target.local$path"),
        "Host-localhost" to listOf("Host: localhost"),
    )

    // ============================ cors_misconfig_probe ============================

    private fun registerCorsProbe(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "cors_misconfig_probe",
            description = "Probe an endpoint for permissive CORS misconfigurations. Sends requests with " +
                "Origin set to attacker-controlled, null, and various reflected variants; reports any " +
                "Access-Control-Allow-Origin reflection paired with Access-Control-Allow-Credentials: true " +
                "(the textbook account-takeover combination).",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"   to S.str("Target host"),
                    "port"   to S.int("Port"),
                    "secure" to S.bool("HTTPS", default = true),
                    "path"   to S.str("Path", default = "/"),
                    "method" to S.enum("HTTP method", listOf("GET", "POST", "OPTIONS"), default = "GET"),
                    "extra_headers" to S.arr("Additional headers (e.g. Authorization)", S.str("hdr")),
                ),
                required = listOf("host"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val path = Args.strOrNull(args, "path") ?: "/"
            val method = (Args.strOrNull(args, "method") ?: "GET").uppercase()
            @Suppress("UNCHECKED_CAST")
            val extra = (args["extra_headers"] as? List<Any?>)?.map { it.toString() } ?: emptyList()
            val service = HttpService.httpService(host, port, secure)

            val origins = listOf(
                "https://evil.example.com",
                "null",
                "https://$host.evil.example.com",
                "https://evil.$host",
                "https://${host.replace(".", "_")}.evil.example.com",
                "https://$host%60evil.example.com",
                "https://$host.evil",
                "http://$host",   // protocol downgrade
            )

            val findings = mutableListOf<Map<String, Any?>>()
            for (origin in origins) {
                val raw = buildRawRequest(method, path, host, extra + listOf("Origin: $origin"))
                val r = sendOne(api, service, raw)
                val acao = r.headerValue("Access-Control-Allow-Origin")
                val acac = r.headerValue("Access-Control-Allow-Credentials")
                val reflectsOrigin = acao != null && (acao == origin || acao == "*")
                val withCreds = acac?.equals("true", ignoreCase = true) == true
                val severity = when {
                    reflectsOrigin && withCreds && acao != "*" -> "critical"
                    reflectsOrigin && withCreds && acao == "*" -> "noteworthy"  // browsers reject this combo
                    reflectsOrigin                             -> "info"
                    else                                       -> null
                }
                if (severity != null) {
                    findings.add(
                        mapOf(
                            "origin_sent"               to origin,
                            "acao_returned"             to acao,
                            "acac_returned"             to acac,
                            "reflects_attacker_origin"  to reflectsOrigin,
                            "credentials_allowed"       to withCreds,
                            "severity"                  to severity,
                            "status_code"               to r.statusCode,
                        ),
                    )
                }
            }
            mapOf(
                "tested_origins" to origins.size,
                "findings"       to findings,
                "finding_count"  to findings.size,
                "summary"        to when {
                    findings.any { it["severity"] == "critical" } -> "CRITICAL: Origin reflection + credentials enabled. Probable account takeover via cross-origin XHR."
                    findings.any { it["severity"] == "noteworthy" } -> "ACAO=* with credentials=true is a server misconfiguration (browsers reject this) but indicates careless CORS."
                    findings.any { it["severity"] == "info" } -> "Server reflects arbitrary origins but doesn't allow credentials. Lower-impact but worth checking sensitive endpoints."
                    else -> "No CORS misconfigurations detected on this path."
                },
            )
        }
    }

    // ============================== shared helpers ==============================

    internal data class Resp(
        val statusCode: Int,
        val bodyLength: Int,
        val headers: List<Pair<String, String>>,
        val body: String,
    ) {
        fun headerValue(name: String): String? = headers
            .firstOrNull { it.first.equals(name, ignoreCase = true) }?.second
    }

    private fun sendOne(api: MontoyaApi, service: HttpService, raw: String): Resp {
        val req = HttpRequest.httpRequest(service, HttpTools.normalizeRawRequest(raw))
        val rr = api.http().sendRequest(req, HttpMode.AUTO)
        val resp = rr.response()
        if (resp == null) return Resp(0, 0, emptyList(), "")
        return Resp(
            statusCode = resp.statusCode().toInt(),
            bodyLength = resp.body().length(),
            headers    = resp.headers().map { it.name() to it.value() },
            body       = resp.bodyToString(),
        )
    }

    private fun buildRawRequest(method: String, path: String, host: String, extraHeaders: List<String>): String {
        val sb = StringBuilder()
        sb.append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
        sb.append("Host: ").append(host).append("\r\n")
        sb.append("User-Agent: burp-mcp-ultimate\r\n")
        sb.append("Accept: */*\r\n")
        sb.append("Connection: close\r\n")
        for (h in extraHeaders) {
            // Allow caller to provide raw "Name: value" lines.
            sb.append(h.trimEnd()).append("\r\n")
        }
        sb.append("\r\n")
        return sb.toString()
    }

    internal data class Anomaly(val type: String, val evidence: String)

    internal fun analyzeAnomaly(baseline: Resp, probe: Resp, marker: String): Anomaly? {
        // 1. Status code change.
        if (probe.statusCode != baseline.statusCode) {
            return Anomaly("status_code_change",
                "${baseline.statusCode} -> ${probe.statusCode}")
        }
        // 2. Marker reflected anywhere in headers or body.
        val reflectedInBody = probe.body.contains(marker)
        val reflectedInHeader = probe.headers.any {
            it.first.contains(marker, ignoreCase = true) || it.second.contains(marker, ignoreCase = true)
        }
        if (reflectedInHeader) return Anomaly("marker_reflected_in_header",
            "marker '$marker' appeared in response headers")
        if (reflectedInBody) return Anomaly("marker_reflected_in_body",
            "marker '$marker' appeared in response body")
        // 3. Significant body-length delta (>= 50 bytes or >= 5%).
        val delta = probe.bodyLength - baseline.bodyLength
        if (delta != 0) {
            val pct = if (baseline.bodyLength == 0) 1.0 else (delta.toDouble() / baseline.bodyLength)
            if (kotlin.math.abs(delta) >= 50 || kotlin.math.abs(pct) >= 0.05) {
                return Anomaly("body_length_change",
                    "delta=${delta}B (${"%.1f".format(pct * 100)}%)")
            }
        }
        // 4. New response header that wasn't in baseline.
        val baseHeaderNames = baseline.headers.map { it.first.lowercase() }.toSet()
        val newHeaders = probe.headers.filter { it.first.lowercase() !in baseHeaderNames }
        if (newHeaders.isNotEmpty()) {
            return Anomaly("new_response_header",
                "added: ${newHeaders.joinToString(", ") { it.first }}")
        }
        return null
    }
}

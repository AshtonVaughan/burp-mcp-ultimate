package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.HandleStore
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object ScannerTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, handles: HandleStore) {

        reg.register(
            name = "scanner_start_crawl",
            description = "Start a Burp crawl from one or more seed URLs. Returns a handle to the Crawl task.",
            inputSchema = S.obj(
                properties = mapOf("seed_urls" to S.arr("Seed URLs", S.str("URL"))),
                required = listOf("seed_urls"),
            ),
        ) { args ->
            val seeds = Args.list(args, "seed_urls").map { it.toString() }
            require(seeds.isNotEmpty()) { "seed_urls must be non-empty" }
            val cfg = CrawlConfiguration.crawlConfiguration(*seeds.toTypedArray())
            val task = api.scanner().startCrawl(cfg)
            mapOf(
                "handle"        to handles.put(task),
                "status"        to task.statusMessage(),
                "request_count" to task.requestCount(),
                "error_count"   to task.errorCount(),
            )
        }

        reg.register(
            name = "scanner_start_audit",
            description = "Active-scan a single request. Returns a handle to the Audit task.",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"    to S.str("Target host"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("HTTPS", default = true),
                    "request" to S.str("Raw request to audit"),
                    "config"  to S.enum("Built-in audit profile",
                        listOf("LEGACY_PASSIVE_AUDIT_CHECKS", "LEGACY_ACTIVE_AUDIT_CHECKS"),
                        default = "LEGACY_ACTIVE_AUDIT_CHECKS"),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host = Args.str(args, "host")
            val secure = Args.bool(args, "secure", true)
            val port = Args.int(args, "port", if (secure) 443 else 80)
            val raw = Args.str(args, "request")
            val cfgName = Args.strOrNull(args, "config") ?: "LEGACY_ACTIVE_AUDIT_CHECKS"
            val req = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
            val cfg = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.valueOf(cfgName))
            val task = api.scanner().startAudit(cfg)
            task.addRequest(req)
            mapOf(
                "handle"        to handles.put(task),
                "status"        to task.statusMessage(),
                "request_count" to task.requestCount(),
                "error_count"   to task.errorCount(),
            )
        }

        reg.register(
            name = "scanner_task_status",
            description = "Get status of a Crawl/Audit task by handle.",
            inputSchema = S.obj(
                properties = mapOf("handle" to S.str("Crawl or Audit handle")),
                required = listOf("handle"),
            ),
        ) { args ->
            val h = Args.str(args, "handle")
            val task = handles.get(h) ?: error("unknown handle")
            // Both Crawl and Audit have statusMessage / requestCount / errorCount via reflection (ScanTask).
            val cls = task.javaClass
            mapOf(
                "class"         to cls.name,
                "status"        to cls.getMethod("statusMessage").invoke(task),
                "request_count" to cls.getMethod("requestCount").invoke(task),
                "error_count"   to cls.getMethod("errorCount").invoke(task),
            )
        }

        reg.register(
            name = "scanner_task_delete",
            description = "Delete a Crawl/Audit task by handle.",
            inputSchema = S.obj(
                properties = mapOf("handle" to S.str("Crawl or Audit handle")),
                required = listOf("handle"),
            ),
        ) { args ->
            val task = handles.get(Args.str(args, "handle")) ?: error("unknown handle")
            task.javaClass.getMethod("delete").invoke(task)
            mapOf("ok" to true)
        }

        reg.register(
            name = "scanner_get_issues",
            description = "List scanner issues currently in the project (Pro only).",
            inputSchema = S.obj(
                properties = mapOf(
                    "url_contains" to S.str("Substring filter on issue URL"),
                    "severity"     to S.enum("Severity filter",
                        listOf("INFORMATION", "LOW", "MEDIUM", "HIGH", "CRITICAL")),
                    "limit"        to S.int("Max items", default = 100),
                ),
            ),
        ) { args ->
            val urlContains = Args.strOrNull(args, "url_contains")
            val severity    = Args.strOrNull(args, "severity")?.uppercase()
            val limit       = Args.int(args, "limit", 100)

            val items = api.siteMap().issues().asSequence()
                .filter { iss ->
                    (urlContains == null || iss.baseUrl().contains(urlContains)) &&
                    (severity == null || iss.severity().name == severity)
                }
                .take(limit).toList()

            mapOf(
                "count" to items.size,
                "issues" to items.map {
                    mapOf(
                        "name"        to it.name(),
                        "severity"    to it.severity().name,
                        "confidence"  to it.confidence().name,
                        "url"         to it.baseUrl(),
                        "detail"      to it.detail(),
                        "remediation" to it.remediation(),
                    )
                },
            )
        }

        reg.register(
            name = "scanner_import_bcheck",
            description = "Import a BCheck definition (Burp's custom scan check DSL).",
            inputSchema = S.obj(
                properties = mapOf(
                    "definition" to S.str("BCheck source"),
                    "enabled"    to S.bool("Enable immediately", default = true),
                ),
                required = listOf("definition"),
            ),
        ) { args ->
            val res = api.scanner().bChecks().importBCheck(
                Args.str(args, "definition"),
                Args.bool(args, "enabled", true),
            )
            mapOf("status" to res.status().name, "errors" to res.importErrors())
        }
    }
}

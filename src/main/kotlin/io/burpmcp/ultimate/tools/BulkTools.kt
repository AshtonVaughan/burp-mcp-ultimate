package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.Progress
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S
import java.util.concurrent.Executors

object BulkTools {

    fun register(reg: ToolRegistry, api: MontoyaApi, progress: Progress) {

        reg.register(
            name = "http_send_batch",
            description = "Send N HTTP requests in parallel and return per-request status + body length. " +
                "Each item is an object: {host, port?, secure?, request, mode?}. " +
                "Header line endings in 'request' are normalized to CRLF; body bytes are preserved. " +
                "Pushes progress notifications.",
            inputSchema = S.obj(
                properties = mapOf(
                    "requests"    to S.arr(
                        desc = "Array of request specs",
                        items = S.obj(
                            properties = mapOf(
                                "host"    to S.str("Target host"),
                                "port"    to S.int("Port (default 443 if secure, else 80)"),
                                "secure"  to S.bool("HTTPS", default = true),
                                "request" to S.str("Raw HTTP request bytes"),
                                "mode"    to S.enum("HTTP version", listOf("auto", "http1", "http2"), default = "auto"),
                            ),
                            required = listOf("host", "request"),
                        ),
                    ),
                    "concurrency" to S.int("Parallel workers", default = 8),
                ),
                required = listOf("requests"),
            ),
        ) { args ->
            @Suppress("UNCHECKED_CAST")
            val items = Args.list(args, "requests") as List<Map<String, Any?>>
            val concurrency = Args.int(args, "concurrency", 8).coerceIn(1, 64)
            val token = progress.start("http_send_batch (${items.size} reqs)")
            val pool = Executors.newFixedThreadPool(concurrency)
            val results = arrayOfNulls<Map<String, Any?>>(items.size)
            try {
                val futures = items.mapIndexed { idx, spec ->
                    pool.submit {
                        results[idx] = try {
                            val host    = spec["host"]?.toString() ?: error("missing host at $idx")
                            val secure  = (spec["secure"] as? Boolean) ?: true
                            val port    = (spec["port"] as? Number)?.toInt() ?: if (secure) 443 else 80
                            val rawIn   = spec["request"]?.toString() ?: error("missing request at $idx")
                            val raw     = HttpTools.normalizeRawRequest(rawIn)
                            val mode    = when (spec["mode"]?.toString()) {
                                "http1" -> HttpMode.HTTP_1; "http2" -> HttpMode.HTTP_2; else -> HttpMode.AUTO
                            }
                            val service = HttpService.httpService(host, port, secure)
                            val req     = HttpRequest.httpRequest(service, raw)
                            val rr      = api.http().sendRequest(req, mode)
                            val resp    = rr.response()
                            mapOf(
                                "index"        to idx,
                                "status_code"  to resp.statusCode().toInt(),
                                "body_length"  to resp.body().length(),
                                "round_trip_ms" to (rr.timingData().orElse(null)
                                    ?.timeBetweenRequestSentAndEndOfResponse()?.toMillis() ?: 0L),
                            )
                        } catch (t: Throwable) {
                            mapOf("index" to idx, "error" to "${t.javaClass.simpleName}: ${t.message}")
                        }
                        progress.tick(token, idx + 1, items.size)
                    }
                }
                futures.forEach { it.get() }
            } finally {
                pool.shutdown()
                progress.end(token, "done")
            }
            val statusHistogram = results.filterNotNull()
                .mapNotNull { it["status_code"] as? Int }
                .groupingBy { it }.eachCount()
            mapOf(
                "count"            to items.size,
                "status_histogram" to statusHistogram,
                "results"          to results.toList(),
            )
        }

        reg.register(
            name = "http_send_race",
            description = "Race-condition variant: send N copies of the SAME request as close to simultaneously as possible (single-packet style).",
            inputSchema = S.obj(
                properties = mapOf(
                    "host"    to S.str("Target host"),
                    "port"    to S.int("Port"),
                    "secure"  to S.bool("HTTPS", default = true),
                    "request" to S.str("Raw HTTP request"),
                    "copies"  to S.int("Number of copies to fire", default = 30),
                ),
                required = listOf("host", "request"),
            ),
        ) { args ->
            val host    = Args.str(args, "host")
            val secure  = Args.bool(args, "secure", true)
            val port    = Args.int(args, "port", if (secure) 443 else 80)
            val raw     = HttpTools.normalizeRawRequest(Args.str(args, "request"))
            val copies  = Args.int(args, "copies", 30).coerceIn(2, 200)
            val service = HttpService.httpService(host, port, secure)
            val reqs    = List(copies) { HttpRequest.httpRequest(service, raw) }
            val started = System.nanoTime()
            val rrs     = api.http().sendRequests(reqs, HttpMode.AUTO)
            val ms      = (System.nanoTime() - started) / 1_000_000
            val byStatus = rrs.mapNotNull { it.response()?.statusCode()?.toInt() }
                .groupingBy { it }.eachCount()
            mapOf(
                "copies"        to copies,
                "wall_time_ms"  to ms,
                "by_status"     to byStatus,
                "first_3_bodies" to rrs.take(3).map { it.response()?.bodyToString()?.take(500) },
            )
        }
    }
}

package io.burpmcp.ultimate.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * Hold-and-decide intercept bridge.
 *
 * The proxy handler thread blocks on a CountDownLatch until either:
 *   (a) the agent calls intercept_resolve(id, ...), or
 *   (b) the per-request timeout (default 30 s) expires, in which case
 *       we fail open (continueWith).
 *
 * Modes:
 *   "observe"        - never hold; fall through (default).
 *   "hold_requests"  - hold incoming requests, agent decides.
 *   "hold_responses" - hold incoming responses, agent decides.
 *   "hold_both"      - hold both directions.
 */
class InterceptQueue(private val timeoutSeconds: Long = 30) {

    enum class Mode { OBSERVE, HOLD_REQUESTS, HOLD_RESPONSES, HOLD_BOTH }
    enum class Verdict { CONTINUE, INTERCEPT, DROP }

    data class Pending(
        val id: String,
        val direction: String,            // "request" or "response"
        val ts: Instant,
        val originalUrl: String,
        val method: String?,
        val statusCode: Int?,
        val rawPreview: String,
        @Volatile var verdict: Verdict? = null,
        @Volatile var modifiedRequest: HttpRequest? = null,
        @Volatile var modifiedResponse: HttpResponse? = null,
        val latch: CountDownLatch = CountDownLatch(1),
        val originalRequest: HttpRequest? = null,
        val originalResponse: HttpResponse? = null,
    )

    @Volatile var mode: Mode = Mode.OBSERVE
    private val pending = ConcurrentHashMap<String, Pending>()
    private val seq = AtomicLong()

    fun install(api: MontoyaApi) {
        api.proxy().registerRequestHandler(object : ProxyRequestHandler {
            override fun handleRequestReceived(req: InterceptedRequest): ProxyRequestReceivedAction {
                if (mode != Mode.HOLD_REQUESTS && mode != Mode.HOLD_BOTH) {
                    return ProxyRequestReceivedAction.continueWith(req)
                }
                val p = enqueueRequest(req)
                if (!p.latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
                    pending.remove(p.id)
                    return ProxyRequestReceivedAction.continueWith(req)
                }
                pending.remove(p.id)
                return when (p.verdict) {
                    Verdict.DROP      -> ProxyRequestReceivedAction.drop()
                    Verdict.INTERCEPT -> ProxyRequestReceivedAction.intercept(p.modifiedRequest ?: req)
                    else              -> ProxyRequestReceivedAction.continueWith(p.modifiedRequest ?: req)
                }
            }
            override fun handleRequestToBeSent(req: InterceptedRequest): ProxyRequestToBeSentAction =
                ProxyRequestToBeSentAction.continueWith(req)
        })
        api.proxy().registerResponseHandler(object : ProxyResponseHandler {
            override fun handleResponseReceived(resp: InterceptedResponse): ProxyResponseReceivedAction {
                if (mode != Mode.HOLD_RESPONSES && mode != Mode.HOLD_BOTH) {
                    return ProxyResponseReceivedAction.continueWith(resp)
                }
                val p = enqueueResponse(resp)
                if (!p.latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
                    pending.remove(p.id)
                    return ProxyResponseReceivedAction.continueWith(resp)
                }
                pending.remove(p.id)
                return when (p.verdict) {
                    Verdict.DROP      -> ProxyResponseReceivedAction.drop()
                    Verdict.INTERCEPT -> ProxyResponseReceivedAction.intercept(p.modifiedResponse ?: resp)
                    else              -> ProxyResponseReceivedAction.continueWith(p.modifiedResponse ?: resp)
                }
            }
            override fun handleResponseToBeSent(resp: InterceptedResponse): ProxyResponseToBeSentAction =
                ProxyResponseToBeSentAction.continueWith(resp)
        })
    }

    private fun enqueueRequest(req: InterceptedRequest): Pending {
        val id = "iq${seq.incrementAndGet()}"
        val p = Pending(
            id              = id,
            direction       = "request",
            ts              = Instant.now(),
            originalUrl     = req.url(),
            method          = req.method(),
            statusCode      = null,
            rawPreview      = req.toString().take(2000),
            originalRequest = req,
        )
        pending[id] = p
        return p
    }

    private fun enqueueResponse(resp: InterceptedResponse): Pending {
        val id = "iq${seq.incrementAndGet()}"
        val p = Pending(
            id               = id,
            direction        = "response",
            ts               = Instant.now(),
            originalUrl      = resp.initiatingRequest().url(),
            method           = resp.initiatingRequest().method(),
            statusCode       = resp.statusCode().toInt(),
            rawPreview       = resp.toString().take(2000),
            originalResponse = resp,
        )
        pending[id] = p
        return p
    }

    fun listPending(): List<Map<String, Any?>> = pending.values.sortedBy { it.ts }.map {
        mapOf(
            "id"          to it.id,
            "direction"   to it.direction,
            "ts"          to it.ts.toString(),
            "url"         to it.originalUrl,
            "method"      to it.method,
            "status_code" to it.statusCode,
            "preview"     to it.rawPreview.take(500),
        )
    }

    fun fullPreview(id: String): String? = pending[id]?.rawPreview

    fun resolve(
        id: String,
        verdict: Verdict,
        modifiedRequest: HttpRequest? = null,
        modifiedResponse: HttpResponse? = null,
    ): Boolean {
        val p = pending[id] ?: return false
        p.verdict = verdict
        if (modifiedRequest  != null) p.modifiedRequest  = modifiedRequest
        if (modifiedResponse != null) p.modifiedResponse = modifiedResponse
        p.latch.countDown()
        return true
    }

    fun pendingCount(): Int = pending.size
}

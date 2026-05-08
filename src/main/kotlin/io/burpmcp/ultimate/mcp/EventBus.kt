package io.burpmcp.ultimate.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import burp.api.montoya.scanner.audit.AuditIssueHandler
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scope.ScopeChange
import burp.api.montoya.scope.ScopeChangeHandler
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Bridge from Burp's handler-style APIs to a poll-based event stream.
 *
 * Channels: proxy_request, proxy_response, http_request, http_response,
 *           scan_issue, scope_change, collaborator_interaction.
 *
 * Each channel keeps a ring buffer of events with a monotonic sequence
 * number. The agent calls events_subscribe(channel) to get a subscription
 * id, then events_poll(subscription_id) to drain new events since the
 * last poll. Subscriptions auto-expire after `ttlSeconds` of no polling.
 */
class EventBus(
    private val capacityPerChannel: Int = 1000,
    private val subscriptionTtlSeconds: Long = 600,
) {

    companion object {
        /** Canonical list of channels installed by [installHandlers]. */
        val KNOWN_CHANNELS: List<String> = listOf(
            "proxy_request", "proxy_response",
            "http_request", "http_response",
            "scan_issue", "scope_change",
            "collaborator_interaction",
        )
    }

    data class Event(val seq: Long, val ts: Instant, val data: Map<String, Any?>)
    data class Channel(val name: String, val ring: ArrayDeque<Event> = ArrayDeque(),
                       val nextSeq: AtomicLong = AtomicLong())
    data class Subscription(val id: String, val channel: String, var cursor: Long, var lastPoll: Instant)

    private val channels = ConcurrentHashMap<String, Channel>()
    private val subs = ConcurrentHashMap<String, Subscription>()
    private val subSeq = AtomicLong()
    val collaboratorClient: CollaboratorClient? get() = collabClientInternal
    private var collabClientInternal: CollaboratorClient? = null

    @Volatile var sseHub: SseHub? = null

    fun installHandlers(api: MontoyaApi) {
        // Proxy request/response (passive observation).
        api.proxy().registerRequestHandler(object : ProxyRequestHandler {
            override fun handleRequestReceived(req: InterceptedRequest): ProxyRequestReceivedAction {
                push("proxy_request", mapOf(
                    "method" to req.method(),
                    "url"    to req.url(),
                ))
                return ProxyRequestReceivedAction.continueWith(req)
            }
            override fun handleRequestToBeSent(req: InterceptedRequest): ProxyRequestToBeSentAction =
                ProxyRequestToBeSentAction.continueWith(req)
        })
        api.proxy().registerResponseHandler(object : ProxyResponseHandler {
            override fun handleResponseReceived(resp: InterceptedResponse): ProxyResponseReceivedAction {
                push("proxy_response", mapOf(
                    "status_code" to resp.statusCode().toInt(),
                    "url"         to resp.initiatingRequest().url(),
                ))
                return ProxyResponseReceivedAction.continueWith(resp)
            }
            override fun handleResponseToBeSent(resp: InterceptedResponse): ProxyResponseToBeSentAction =
                ProxyResponseToBeSentAction.continueWith(resp)
        })

        // Http handler (every outbound HTTP from Burp tools).
        api.http().registerHttpHandler(object : HttpHandler {
            override fun handleHttpRequestToBeSent(r: HttpRequestToBeSent): RequestToBeSentAction {
                push("http_request", mapOf(
                    "tool"   to r.toolSource().toolType().name,
                    "method" to r.method(),
                    "url"    to r.url(),
                ))
                return RequestToBeSentAction.continueWith(r)
            }
            override fun handleHttpResponseReceived(r: HttpResponseReceived): ResponseReceivedAction {
                push("http_response", mapOf(
                    "tool"        to r.toolSource().toolType().name,
                    "status_code" to r.statusCode().toInt(),
                    "url"         to r.initiatingRequest().url(),
                ))
                return ResponseReceivedAction.continueWith(r)
            }
        })

        // Scanner audit issues.
        api.scanner().registerAuditIssueHandler(AuditIssueHandler { issue: AuditIssue ->
            push("scan_issue", mapOf(
                "name"       to issue.name(),
                "severity"   to issue.severity().name,
                "confidence" to issue.confidence().name,
                "url"        to issue.baseUrl(),
            ))
        })

        // Scope changes.
        api.scope().registerScopeChangeHandler(ScopeChangeHandler { _: ScopeChange ->
            push("scope_change", mapOf("ts" to Instant.now().toString()))
        })

        // Collaborator client + interaction polling-on-demand.
        // We keep a long-lived client; the events_poll tool can drain it.
        collabClientInternal = api.collaborator().createClient()
    }

    /** Drain any new collaborator interactions and push them into the channel. */
    fun drainCollaborator() {
        val c = collabClientInternal ?: return
        for (i in c.allInteractions) {
            push("collaborator_interaction", mapOf(
                "type"        to i.type().name,
                "id"          to i.id().toString(),
                "client_ip"   to i.clientIp().hostAddress,
                "time_stamp"  to i.timeStamp().toString(),
                "custom_data" to i.customData().orElse(null),
            ))
        }
    }

    // --- channel mechanics ---

    /** Public push entry point used by other Burp callbacks (context menu etc). */
    fun pushExternal(channelName: String, data: Map<String, Any?>) = push(channelName, data)

    @Synchronized
    private fun push(channelName: String, data: Map<String, Any?>) {
        val ch = channels.computeIfAbsent(channelName) { Channel(it) }
        val seq = ch.nextSeq.incrementAndGet()
        ch.ring.addLast(Event(seq, Instant.now(), data))
        while (ch.ring.size > capacityPerChannel) ch.ring.removeFirst()
        // Best-effort push to any connected SSE client.
        sseHub?.notify("notifications/event", mapOf(
            "channel" to channelName,
            "seq"     to seq,
            "data"    to data,
        ))
    }

    fun subscribe(channelName: String): Subscription {
        val sub = Subscription(
            id        = "s${subSeq.incrementAndGet()}",
            channel   = channelName,
            cursor    = 0L,
            lastPoll  = Instant.now(),
        )
        subs[sub.id] = sub
        return sub
    }

    fun unsubscribe(id: String): Boolean = subs.remove(id) != null

    @Synchronized
    fun poll(subscriptionId: String, max: Int): List<Event> {
        val sub = subs[subscriptionId]
            ?: throw McpException(ErrorCodes.INVALID_PARAMS, "no subscription: $subscriptionId")
        sub.lastPoll = Instant.now()
        if (sub.channel == "collaborator_interaction") drainCollaborator()
        val ch = channels[sub.channel] ?: return emptyList()
        val events = ch.ring.filter { it.seq > sub.cursor }.take(max)
        events.lastOrNull()?.let { sub.cursor = it.seq }
        evictExpiredSubs()
        return events
    }

    fun listSubscriptions(): List<Map<String, Any?>> = subs.values.map {
        mapOf(
            "id"         to it.id,
            "channel"    to it.channel,
            "cursor"     to it.cursor,
            "last_poll"  to it.lastPoll.toString(),
        )
    }

    /**
     * Returns every known channel with its current buffered count. Channels
     * never observed yet appear with 0 so callers can discover what's
     * subscribable without trial-and-error against [subscribe].
     */
    fun listChannels(): Map<String, Int> {
        val live = channels.mapValues { it.value.ring.size }
        return KNOWN_CHANNELS.associateWith { live[it] ?: 0 } +
               live.filterKeys { it !in KNOWN_CHANNELS }
    }

    private fun evictExpiredSubs() {
        val cutoff = Instant.now().minusSeconds(subscriptionTtlSeconds)
        subs.entries.removeIf { it.value.lastPoll.isBefore(cutoff) }
    }
}

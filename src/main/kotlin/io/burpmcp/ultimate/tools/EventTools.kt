package io.burpmcp.ultimate.tools

import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.EventBus
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object EventTools {

    fun register(reg: ToolRegistry, events: EventBus) {

        reg.register(
            name = "events_subscribe",
            description = "Subscribe to one event channel (poll-based handler bridge). " +
                "Call events_list_channels first to discover available channels.",
            inputSchema = S.obj(
                properties = mapOf("channel" to S.enum("Channel", EventBus.KNOWN_CHANNELS)),
                required = listOf("channel"),
            ),
        ) { args ->
            val sub = events.subscribe(Args.str(args, "channel"))
            mapOf("subscription_id" to sub.id, "channel" to sub.channel)
        }

        reg.register(
            name = "events_poll",
            description = "Poll a subscription for new events since the last call. Returns up to `max` events.",
            inputSchema = S.obj(
                properties = mapOf(
                    "subscription_id" to S.str("Subscription id from events_subscribe"),
                    "max"             to S.int("Max events", default = 100),
                ),
                required = listOf("subscription_id"),
            ),
        ) { args ->
            val id  = Args.str(args, "subscription_id")
            val max = Args.int(args, "max", 100)
            val items = events.poll(id, max).map {
                mapOf("seq" to it.seq, "ts" to it.ts.toString()) + it.data
            }
            mapOf("count" to items.size, "events" to items)
        }

        reg.register(
            name = "events_unsubscribe",
            description = "Drop a subscription.",
            inputSchema = S.obj(
                properties = mapOf("subscription_id" to S.str("Subscription id")),
                required = listOf("subscription_id"),
            ),
        ) { args -> mapOf("dropped" to events.unsubscribe(Args.str(args, "subscription_id"))) }

        reg.register(
            name = "events_list_channels",
            description = "List every supported event channel with its current buffered count. " +
                "Channels with no events yet appear with count=0 so they're still discoverable.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            mapOf("channels" to events.listChannels())
        }

        reg.register(
            name = "events_list_subscriptions",
            description = "List active subscriptions.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ -> mapOf("subscriptions" to events.listSubscriptions()) }
    }
}

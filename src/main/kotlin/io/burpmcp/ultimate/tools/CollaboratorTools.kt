package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object CollaboratorTools {

    @Volatile private var client: CollaboratorClient? = null

    private fun client(api: MontoyaApi): CollaboratorClient {
        var c = client
        if (c == null) {
            synchronized(this) {
                c = client ?: api.collaborator().createClient().also { client = it }
            }
        }
        return c!!
    }

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "collaborator_generate_payload",
            description = "Generate a Burp Collaborator payload (subdomain) for OOB testing. Optional custom_data is stored on the server and returned with matching interactions.",
            inputSchema = S.obj(
                properties = mapOf(
                    "custom_data" to S.str("Optional context tag returned with interactions"),
                ),
            ),
        ) { args ->
            val ctx = Args.strOrNull(args, "custom_data")
            val payload = if (ctx != null) client(api).generatePayload(ctx)
                          else client(api).generatePayload()
            mapOf(
                "payload"        to payload.toString(),
                "interaction_id" to payload.id().toString(),
                "custom_data"    to ctx,
            )
        }

        reg.register(
            name = "collaborator_poll_interactions",
            description = "Poll Collaborator for interactions (DNS, HTTP, SMTP) recorded since the last poll.",
            inputSchema = S.obj(
                properties = mapOf("limit" to S.int("Max items to return", default = 100)),
            ),
        ) { args ->
            val limit = Args.int(args, "limit", 100)
            val interactions = client(api).allInteractions.take(limit)
            mapOf(
                "count" to interactions.size,
                "items" to interactions.map { i ->
                    mapOf(
                        "type"          to i.type().name,
                        "id"            to i.id().toString(),
                        "client_ip"     to i.clientIp().hostAddress,
                        "time_stamp"    to i.timeStamp().toString(),
                        "custom_data"   to i.customData().orElse(null),
                        "dns_query"     to i.dnsDetails().orElse(null)?.query()?.toString(),
                        "dns_type"      to i.dnsDetails().orElse(null)?.queryType()?.name,
                        "http_request"  to i.httpDetails().orElse(null)?.requestResponse()?.request()?.toString(),
                        "smtp_protocol" to i.smtpDetails().orElse(null)?.protocol()?.name,
                        "smtp_convo"    to i.smtpDetails().orElse(null)?.conversation(),
                    )
                },
            )
        }

        reg.register(
            name = "collaborator_server_info",
            description = "Get the Collaborator server hostname this client is using.",
            inputSchema = S.obj(properties = emptyMap()),
        ) { _ ->
            mapOf(
                "server" to client(api).server().address(),
                "literal_address" to client(api).server().isLiteralAddress,
            )
        }
    }

    private val CollaboratorClient.allInteractions
        get() = getAllInteractions()
}

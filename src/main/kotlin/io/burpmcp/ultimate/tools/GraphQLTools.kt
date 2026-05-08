package io.burpmcp.ultimate.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.burpmcp.ultimate.mcp.Args
import io.burpmcp.ultimate.mcp.Json
import io.burpmcp.ultimate.mcp.ToolRegistry
import io.burpmcp.ultimate.mcp.ToolRegistry.Schema as S

object GraphQLTools {

    private const val INTROSPECTION_QUERY = """query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields(includeDeprecated: true) {
        name description
        args { name description defaultValue type { ...TypeRef } }
        type { ...TypeRef }
        isDeprecated deprecationReason
      }
      inputFields { name description defaultValue type { ...TypeRef } }
      interfaces { ...TypeRef }
      enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason }
      possibleTypes { ...TypeRef }
    }
    directives { name description locations args { name description defaultValue type { ...TypeRef } } }
  }
}
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
"""

    private fun postJson(api: MontoyaApi, url: String, payload: String): Map<String, Any?> {
        val u = java.net.URI(url)
        val host = u.host
        val secure = u.scheme.equals("https", ignoreCase = true)
        val port = if (u.port == -1) (if (secure) 443 else 80) else u.port
        val path = u.rawPath.ifEmpty { "/" } + (if (u.rawQuery != null) "?${u.rawQuery}" else "")
        val payloadBytes = payload.toByteArray(Charsets.UTF_8)
        val raw = buildString {
            append("POST ").append(path).append(" HTTP/1.1\r\n")
            append("Host: ").append(host).append("\r\n")
            append("Content-Type: application/json\r\n")
            append("Accept: application/json\r\n")
            append("User-Agent: burp-mcp-ultimate\r\n")
            append("Connection: close\r\n")
            append("Content-Length: ").append(payloadBytes.size).append("\r\n")
            append("\r\n")
            append(payload)
        }
        val req = HttpRequest.httpRequest(HttpService.httpService(host, port, secure), raw)
        val rr = api.http().sendRequest(req, HttpMode.AUTO)
        val resp = rr.response()
        val statusCode = resp?.statusCode()?.toInt() ?: 0
        val body = resp?.bodyToString() ?: ""
        val headers = resp?.headers()?.map {
            mapOf("name" to it.name(), "value" to it.value())
        } ?: emptyList<Map<String, String>>()
        return mapOf(
            "status_code" to statusCode,
            "headers"     to headers,
            "body"        to body,
            "request_sent" to raw,
        )
    }

    fun register(reg: ToolRegistry, api: MontoyaApi) {

        reg.register(
            name = "graphql_introspect",
            description = "Run a full GraphQL introspection query against the endpoint URL.",
            inputSchema = S.obj(
                properties = mapOf("url" to S.str("Full GraphQL endpoint URL")),
                required = listOf("url"),
            ),
        ) { args ->
            val payload = Json.write(mapOf("query" to INTROSPECTION_QUERY))
            postJson(api, Args.str(args, "url"), payload)
        }

        reg.register(
            name = "graphql_query",
            description = "Run a single GraphQL query/mutation. Optional variables.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url"           to S.str("Endpoint URL"),
                    "query"         to S.str("GraphQL query string"),
                    "operation_name" to S.str("Operation name"),
                    "variables_json" to S.str("Variables as a JSON object"),
                ),
                required = listOf("url", "query"),
            ),
        ) { args ->
            val payloadMap = mutableMapOf<String, Any?>("query" to Args.str(args, "query"))
            Args.strOrNull(args, "operation_name")?.let { payloadMap["operationName"] = it }
            Args.strOrNull(args, "variables_json")?.let {
                @Suppress("UNCHECKED_CAST")
                payloadMap["variables"] = Json.mapper.readValue(it, Map::class.java) as Map<String, Any?>
            }
            postJson(api, Args.str(args, "url"), Json.write(payloadMap))
        }

        reg.register(
            name = "graphql_batched_query",
            description = "Send a batched query (array of operations) to defeat aliasing throttling and exfiltrate fields per request.",
            inputSchema = S.obj(
                properties = mapOf(
                    "url"     to S.str("Endpoint URL"),
                    "queries" to S.arr("Array of {query, operationName?, variables?}", S.str("op")),
                ),
                required = listOf("url", "queries"),
            ),
        ) { args ->
            val ops = Args.list(args, "queries").map { it }
            postJson(api, Args.str(args, "url"), Json.write(ops))
        }

        reg.register(
            name = "graphql_field_suggestions",
            description = "Probe the endpoint for field suggestions (server returns 'Did you mean ...' on typos when introspection is disabled).",
            inputSchema = S.obj(
                properties = mapOf(
                    "url"   to S.str("Endpoint URL"),
                    "type"  to S.str("Type name to probe", default = "Query"),
                    "field" to S.str("Bogus field name", default = "_zzz_burp_mcp"),
                ),
                required = listOf("url"),
            ),
        ) { args ->
            val type  = Args.strOrNull(args, "type")  ?: "Query"
            val field = Args.strOrNull(args, "field") ?: "_zzz_burp_mcp"
            val payload = Json.write(mapOf("query" to "query { $field }"))
            val resp = postJson(api, Args.str(args, "url"), payload)
            val body = resp["body"]?.toString() ?: ""
            val suggestions = Regex("Did you mean \"([^\"]+)\"")
                .findAll(body).map { it.groupValues[1] }.toList()
            mapOf(
                "status_code" to resp["status_code"],
                "type"        to type,
                "probed"      to field,
                "suggestions" to suggestions,
                "raw_body"    to body.take(2000),
            )
        }
    }
}

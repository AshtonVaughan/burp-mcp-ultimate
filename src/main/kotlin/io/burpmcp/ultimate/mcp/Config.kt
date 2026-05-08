package io.burpmcp.ultimate.mcp

/**
 * Server-wide config sourced from env vars or system properties.
 * Wired in BurpMcpUltimateExtension.
 */
data class ServerConfig(
    val host: String,
    val port: Int,
    val token: String?,
    /** Comma-separated list of allowed CORS origins, or "*" for any. Default "*". */
    val corsOrigins: List<String>,
    /** Per-session ceiling: max tool calls in a 10-second window. 0 = unlimited. */
    val rateLimitCallsPer10s: Int,
    /** Editor-capture is treated as stale after this many seconds. */
    val editorStaleSeconds: Long,
) {
    companion object {
        fun fromEnvironment(): ServerConfig {
            fun env(k: String) = System.getProperty(k) ?: System.getenv(k)
            val origins = env("BURP_MCP_CORS_ORIGINS")
                ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                ?: listOf("*")
            return ServerConfig(
                host                = env("BURP_MCP_HOST")  ?: "127.0.0.1",
                port                = env("BURP_MCP_PORT")?.toIntOrNull() ?: 9444,
                token               = env("BURP_MCP_TOKEN"),
                corsOrigins         = origins,
                rateLimitCallsPer10s = env("BURP_MCP_RATE_LIMIT")?.toIntOrNull() ?: 0,
                editorStaleSeconds  = env("BURP_MCP_EDITOR_STALE_SECONDS")?.toLongOrNull() ?: 600,
            )
        }
    }
}

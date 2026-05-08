package io.burpmcp.ultimate.prompts

import io.burpmcp.ultimate.mcp.PromptRegistry
import io.burpmcp.ultimate.mcp.PromptRegistry.PromptArg

object CorePrompts {

    fun register(p: PromptRegistry) {

        p.register(
            name        = "audit_auth_flow",
            description = "Step-by-step audit of an authentication / session flow on a target host.",
            arguments   = listOf(
                PromptArg("target_host", "The host to audit", required = true),
                PromptArg("notes", "Any prior notes / scope hints", required = false),
            ),
        ) { args ->
            """
You are auditing the authentication and session flow of `${args["target_host"]}` using Burp Suite Pro through the burp-mcp-ultimate MCP server.

Step through:
1. Map the auth surface. Use `proxy_history` filtered by url_contains the target, plus `sitemap_search url_prefix=https://${args["target_host"]}` to find /login, /logout, /register, /reset, /oauth, /sso, /token, /refresh, /sessions endpoints.
2. For every endpoint found, capture a representative request as a handle (`http_request_build` from the URL).
3. For each, test the standard auth weaknesses: credential stuffing (Intruder), missing rate limit, weak password policy, JWT alg confusion / kid injection (`util_jwt_decode`), session fixation, lack of token rotation on privilege change, IDOR on /sessions DELETE.
4. Use `events_subscribe channel=scan_issue` and `scanner_start_audit` on each captured request. Poll for issues.
5. For anything interesting, set an annotation (`annotation_set highlight=ORANGE notes='auth: ...'`) so the human reviewer sees it in the proxy history.

Notes from the operator: ${args["notes"] ?: "(none)"}

Report findings as a structured list keyed by endpoint, severity, and reproduction steps.
            """.trimIndent()
        }

        p.register(
            name        = "find_idor_pairs",
            description = "Run an IDOR sweep across two authenticated user sessions.",
            arguments   = listOf(
                PromptArg("user_a_handle", "Handle to a request authenticated as user A", required = true),
                PromptArg("user_b_handle", "Handle to a request authenticated as user B", required = true),
            ),
        ) { args ->
            """
IDOR sweep using burp-mcp-ultimate.

Inputs:
- A canonical request authenticated as user A: handle `${args["user_a_handle"]}`
- The same kind of request authenticated as user B: handle `${args["user_b_handle"]}`

Procedure:
1. `http_request_inspect` both handles. Identify all path segments, query params, header values, body keys that contain ids (numeric, UUID, slug).
2. For every such field, build A' = A but with B's value, and B' = B but with A's value, via `http_request_mutate`.
3. Send each mutated pair via `http_send_raw` and diff the responses against the originals.
4. Cross-account access = response equals the OTHER user's normal response = IDOR.
5. Annotate any finding (`annotation_set highlight=RED notes='IDOR on <field>'`) and save the request/response pair via `persist_set_request_response` so it survives a Burp restart.

Return a table: field, A->B result, B->A result, severity.
            """.trimIndent()
        }

        p.register(
            name        = "find_ssrf",
            description = "Hunt SSRF on a captured request handle.",
            arguments   = listOf(
                PromptArg("request_handle", "Handle to a request that fetches a URL", required = true),
            ),
        ) { args ->
            """
SSRF sweep for handle `${args["request_handle"]}`.

1. `montoya_inspect target=${args["request_handle"]}`. Find every parameter value that looks like a URL or hostname.
2. For each, generate a Collaborator payload (`collaborator_generate_payload`) and substitute it in via `http_request_mutate`.
3. Send via `http_send_raw`.
4. Poll `collaborator_poll_interactions`. DNS-only hits = blind SSRF. HTTP hits = full SSRF.
5. For each confirmed: also try `http://169.254.169.254/latest/meta-data/` (AWS), `http://metadata.google.internal/`, `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure), and gopher://, file://, dict:// schemes.
6. Annotate findings (`annotation_set highlight=RED notes='SSRF: <vector>'`).
            """.trimIndent()
        }

        p.register(
            name        = "analyze_jwt",
            description = "Walk through a JWT looking for common attacks.",
            arguments   = listOf(
                PromptArg("token", "The JWT to analyse", required = true),
            ),
        ) { args ->
            """
Analyse JWT.

1. `oauth_decode_access_token token=${args["token"]}` to get header/payload/alg.
2. Check alg: 'none' -> trivially forge. HS256 with weak/known secret -> brute force locally. RS256 -> try alg-confusion via `jwt_alg_confusion` (need server's public key from /jwks.json or cert).
3. Inspect payload: weak iss/sub/aud, missing exp, predictable jti, role claim that looks server-trusted.
4. Test kid injection: `jwt_kid_inject` with values like `../../../dev/null`, `' UNION SELECT ...`, `http://attacker/key`.
5. If JWE: identify enc + alg, look for known weaknesses (alg=dir with predictable key, A128CBC-HS256 padding oracle).
6. Try replay across users/sessions to confirm proper binding.
            """.trimIndent()
        }

        p.register(
            name        = "audit_oauth_flow",
            description = "Audit an OAuth2/OIDC flow against an issuer.",
            arguments   = listOf(
                PromptArg("issuer", "OIDC issuer URL", required = true),
            ),
        ) { args ->
            """
OAuth/OIDC audit for `${args["issuer"]}`.

1. `oidc_discover issuer=${args["issuer"]}`. Note authorization_endpoint, token_endpoint, jwks_uri, supported response_types, supported_grant_types, supported_response_modes.
2. Authorization code with PKCE (`oauth_build_pkce`) is the safe default. Flag if implicit / hybrid flows are still allowed.
3. Test redirect_uri validation: trailing slash, path traversal, open redirect via fragment, `http://attacker.example.com.legitimate.example.com`, `javascript:` scheme, `data:` scheme.
4. Test state parameter: missing, predictable, reusable.
5. Test scope upgrade: ask for an over-broad scope and see if it's silently granted.
6. Test refresh token rotation, single-use, lifetime.
7. Inspect issued JWTs (`oauth_decode_access_token`) for weak alg / leaked claims.
            """.trimIndent()
        }

        p.register(
            name        = "find_race_conditions",
            description = "Race-condition hunt against a captured request.",
            arguments   = listOf(
                PromptArg("request_handle", "Handle to a state-mutating request", required = true),
                PromptArg("copies", "Parallel copy count", required = false),
            ),
        ) { args ->
            val copies = args["copies"] ?: "30"
            """
Race-condition test for handle `${args["request_handle"]}`.

1. `montoya_inspect target=${args["request_handle"]}`. Confirm the request mutates state (POST/PUT/PATCH/DELETE on /balance, /vote, /apply-coupon, /redeem, /transfer, /withdraw).
2. Snapshot the relevant resource state (current balance, current vote count) by sending a GET.
3. `http_send_race host=... request=... copies=$copies` — fires N parallel copies via Burp's bulk path (HTTP/2 single-frame style when available).
4. Snapshot the post-state. If the resource changed by more than 1 unit, race confirmed.
5. Try escalating: 2x, 5x, 10x copies. Find the threshold at which the bug stops/starts firing.
6. Annotate (`annotation_set highlight=RED notes='race window N=...'`) and persist (`persist_set_request_response`).
            """.trimIndent()
        }

        p.register(
            name        = "audit_file_upload",
            description = "Walkthrough for testing a file-upload endpoint.",
            arguments   = listOf(
                PromptArg("upload_url", "Endpoint URL", required = true),
            ),
        ) { args ->
            """
File-upload audit for `${args["upload_url"]}`.

Cover:
1. Allowed content-types (server enforcement vs client filter): try image/png, application/zip, text/html, application/x-php, application/x-shellscript.
2. Magic-byte vs extension confusion (PNG header + .php extension).
3. Path traversal in filename: `../../..\\..\\windows\\System32\\drivers\\etc\\hosts`.
4. Null byte: `evil.php%00.png`.
5. Polyglot files: GIF89a + PHP, SVG + JS.
6. Server-side parsing (image library RCE, ZIP-slip).
7. Where does it land? Predictable URL? Direct browse? Stored XSS via SVG?
8. Post-upload, look for the file URL in `proxy_history` and try to retrieve it as the attacker.

Annotate findings; persist any working PoC handle via `persist_set_request_response`.
            """.trimIndent()
        }

        p.register(
            name        = "analyze_graphql_schema",
            description = "Run introspection then walk the resulting schema for sensitive fields.",
            arguments   = listOf(
                PromptArg("url", "GraphQL endpoint", required = true),
            ),
        ) { args ->
            """
GraphQL schema audit for `${args["url"]}`.

1. `graphql_introspect url=${args["url"]}`. If it returns 401/403/empty, try `graphql_field_suggestions` to bypass the introspection block.
2. From the schema:
   - List every Query field whose name suggests data exposure: user(id), users, admin, secret, internal, debug, raw, all*.
   - List every Mutation that mutates auth state: setRole, grant*, impersonate, deleteAll, exportAll.
   - List every type that has fields like password, ssn, token, secret, creditCard.
3. For each candidate, build a query (`graphql_query`) selecting that field. Note auth requirements.
4. Test field aliasing for rate-limit bypass: query the same field 200 times with aliases via `graphql_batched_query`.
5. Test depth attack: deeply nested `{ user { friends { friends { friends { ... } } } } }`.
6. Annotate / persist anything that returns data you should not have.
            """.trimIndent()
        }

        p.register(
            name        = "analyze_response",
            description = "Look at a captured response handle and surface anything notable.",
            arguments   = listOf(
                PromptArg("response_handle", "Handle to an HttpResponse or HttpRequestResponse", required = true),
            ),
        ) { args ->
            """
Use `montoya_inspect target=${args["response_handle"]}` to read every getter on the response.

Look for:
- Reflected input from the request (XSS / SSRF surface).
- Sensitive data in headers (Server, X-Powered-By, Set-Cookie without HttpOnly/Secure/SameSite).
- Stack traces, debug info, internal IPs, software versions.
- Misleading status codes (200 with error body).
- Cache-Control issues for sensitive responses.
- CORS misconfiguration (Access-Control-Allow-Origin: * with credentials).

For each, cite the exact header/body excerpt and propose a follow-up tool call.
            """.trimIndent()
        }
    }
}

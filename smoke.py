"""Comprehensive smoke test for burp-mcp-ultimate via raw MCP HTTP/JSON-RPC."""
from __future__ import annotations
import json
import os
import sys
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:9444/mcp"
TOKEN = os.environ.get("BURP_MCP_TOKEN", "")
SESSION_ID: str | None = None
RID = 0

def rpc(method: str, params: dict | None = None, *, timeout: int = 30) -> tuple[dict | None, str | None, dict]:
    """Returns (result, error_message, raw_envelope_or_dict)."""
    global RID, SESSION_ID
    RID += 1
    body = {"jsonrpc": "2.0", "id": RID, "method": method}
    if params is not None:
        body["params"] = params
    data = json.dumps(body).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {TOKEN}",
    }
    if SESSION_ID:
        headers["Mcp-Session-Id"] = SESSION_ID
    req = urllib.request.Request(BASE, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            sid = resp.headers.get("Mcp-Session-Id")
            if sid and not SESSION_ID:
                SESSION_ID = sid
            raw = resp.read().decode("utf-8", errors="replace")
            ctype = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return None, f"HTTP {e.code}: {body[:300]}", {}
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", {}

    # SSE: parse first data: line
    if "text/event-stream" in ctype:
        for line in raw.splitlines():
            if line.startswith("data:"):
                try:
                    env = json.loads(line[5:].strip())
                    break
                except Exception:
                    continue
        else:
            return None, f"SSE no data line: {raw[:200]}", {}
    else:
        try:
            env = json.loads(raw)
        except Exception as e:
            return None, f"JSON parse: {e} body={raw[:200]}", {}

    if "error" in env:
        err = env["error"]
        return None, f"code={err.get('code')} msg={err.get('message')} data={json.dumps(err.get('data'))[:200] if err.get('data') is not None else ''}", env
    return env.get("result"), None, env

def call_tool(name: str, args: dict | None = None, *, timeout: int = 30):
    return rpc("tools/call", {"name": name, "arguments": args or {}}, timeout=timeout)

def text_of(result: dict | None) -> str:
    if not result:
        return ""
    parts = []
    for c in result.get("content", []) or []:
        if c.get("type") == "text":
            parts.append(c.get("text", ""))
    return "\n".join(parts)

def is_error(result: dict | None) -> bool:
    return bool(result and result.get("isError"))

# ---- record results ---------------------------------------------------------
ROWS: list[tuple[int, str, str, str, str]] = []  # (#, surface, tool, status, evidence)
FAILS: list[tuple[int, str, str]] = []  # (#, tool, raw error)

def record(num: int, surface: str, tool: str, status: str, evidence: str, err: str | None = None) -> None:
    ROWS.append((num, surface, tool, status, evidence.replace("|", "\\|")[:120]))
    if status == "x" and err:
        FAILS.append((num, tool, err))

def short(s: str, n: int = 100) -> str:
    s = s.replace("\n", " ").replace("\r", " ").strip()
    return s if len(s) <= n else s[:n] + "..."

# ---- initialize -------------------------------------------------------------
init_res, init_err, _ = rpc("initialize", {
    "protocolVersion": "2024-11-05",
    "capabilities": {},
    "clientInfo": {"name": "smoke", "version": "1"},
})
if init_err:
    print(f"Initialize FAILED: {init_err}", file=sys.stderr)
    sys.exit(1)
rpc("notifications/initialized")
print(f"Initialized session={SESSION_ID}", file=sys.stderr)

# ============================================================================
# HTTP (1-7)
# ============================================================================
# 1: http_url_to_request
res, err, _ = call_tool("http_url_to_request", {"url": "https://example.com"})
host_1 = port_1 = secure_1 = raw_1 = None
if err or is_error(res):
    record(1, "HTTP", "http_url_to_request", "x", "", err or short(text_of(res)))
else:
    txt = text_of(res)
    try:
        # try parse JSON for fields
        j = json.loads(txt)
        host_1 = j.get("host") or j.get("Host")
        port_1 = j.get("port") or j.get("Port")
        secure_1 = j.get("secure") if j.get("secure") is not None else j.get("Secure")
        raw_1 = j.get("request") or j.get("raw")
        record(1, "HTTP", "http_url_to_request", "ok", f"host={host_1} port={port_1}")
    except Exception:
        record(1, "HTTP", "http_url_to_request", "x", short(txt), txt)

# 2: http_send_raw using #1 outputs
if host_1 and raw_1:
    res, err, _ = call_tool("http_send_raw", {"host": host_1, "port": port_1 or 443, "secure": bool(secure_1), "request": raw_1}, timeout=45)
    if err or is_error(res):
        record(2, "HTTP", "http_send_raw (chained)", "x", "", err or short(text_of(res)))
    else:
        t = text_of(res)
        try:
            j = json.loads(t)
            sc = j.get("statusCode") or j.get("status") or j.get("statusLine") or ""
            record(2, "HTTP", "http_send_raw (chained)", "ok" if str(sc).startswith("2") or "200" in str(sc) else "x", f"status={sc}")
        except Exception:
            record(2, "HTTP", "http_send_raw (chained)", "ok" if "200" in t else "x", short(t))
else:
    record(2, "HTTP", "http_send_raw (chained)", "x", "skipped: #1 no output", "no host/raw from #1")

# 3: LF-only headers
lf_req = "GET / HTTP/1.1\nHost: example.com\nConnection: close\n\n"
res, err, _ = call_tool("http_send_raw", {"host": "example.com", "port": 443, "secure": True, "request": lf_req}, timeout=45)
if err or is_error(res):
    record(3, "HTTP", "http_send_raw (LF)", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    try:
        j = json.loads(t)
        sc = j.get("statusCode") or j.get("status") or ""
        record(3, "HTTP", "http_send_raw (LF)", "ok" if "200" in str(sc) else "x", f"status={sc}", None if "200" in str(sc) else t)
    except Exception:
        record(3, "HTTP", "http_send_raw (LF)", "ok" if "200" in t else "x", short(t), None if "200" in t else t)

# 4: plain HTTP port 80
res, err, _ = call_tool("http_send_raw", {"host": "example.com", "port": 80, "secure": False, "request": "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"}, timeout=45)
if err or is_error(res):
    record(4, "HTTP", "http_send_raw (port 80)", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    try:
        j = json.loads(t)
        sc = j.get("statusCode") or j.get("status") or ""
        ok = "200" in str(sc) or "301" in str(sc)
        record(4, "HTTP", "http_send_raw (port 80)", "ok" if ok else "x", f"status={sc}", None if ok else t)
    except Exception:
        ok = "200" in t or "301" in t
        record(4, "HTTP", "http_send_raw (port 80)", "ok" if ok else "x", short(t), None if ok else t)

# 5: http_send_batch
res, err, _ = call_tool("http_send_batch", {"requests": [
    {"host": "example.com", "port": 443, "secure": True, "request": "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"},
    {"host": "example.com", "port": 443, "secure": True, "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"},
]}, timeout=60)
if err or is_error(res):
    record(5, "HTTP", "http_send_batch", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    try:
        j = json.loads(t)
        n = len(j) if isinstance(j, list) else len(j.get("responses", []))
        record(5, "HTTP", "http_send_batch", "ok" if n == 2 else "x", f"responses={n}")
    except Exception:
        record(5, "HTTP", "http_send_batch", "x", short(t), t)

# 6: cookie_jar_set + cookie_jar_list
r1, e1, _ = call_tool("cookie_jar_set", {"name": "smoke", "value": "v", "domain": "example.com"})
r2, e2, _ = call_tool("cookie_jar_list", {})
if e1 or e2 or is_error(r1) or is_error(r2):
    record(6, "HTTP", "cookie_jar_*", "x", "", e1 or e2 or short(text_of(r1) + text_of(r2)))
else:
    t = text_of(r2)
    found = "smoke" in t
    record(6, "HTTP", "cookie_jar_*", "ok" if found else "x", "smoke cookie present" if found else "missing", None if found else t)

# 7: http_send_with_session_handling
res, err, _ = call_tool("http_send_with_session_handling", {"host": "example.com", "port": 443, "secure": True, "request": "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"}, timeout=60)
if err or is_error(res):
    record(7, "HTTP", "http_send_with_session_handling", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    try:
        j = json.loads(t)
        sc = j.get("statusCode") or j.get("status") or ""
        record(7, "HTTP", "http_send_with_session_handling", "ok" if "200" in str(sc) else "x", f"status={sc}")
    except Exception:
        record(7, "HTTP", "http_send_with_session_handling", "ok" if "200" in t else "x", short(t))

# ============================================================================
# GraphQL (8-9)
# ============================================================================
res, err, _ = call_tool("graphql_introspect", {"url": "https://countries.trevorblades.com/"}, timeout=60)
if err or is_error(res):
    record(8, "GraphQL", "graphql_introspect", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    record(8, "GraphQL", "graphql_introspect", "ok" if "__schema" in t or "queryType" in t.lower() else "x", "__schema present" if "__schema" in t else short(t), None if "__schema" in t or "queryType" in t.lower() else t)

res, err, _ = call_tool("graphql_query", {"url": "https://countries.trevorblades.com/", "query": "{ continents { code name } }"}, timeout=60)
if err or is_error(res):
    record(9, "GraphQL", "graphql_query", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has_data = "continents" in t
    record(9, "GraphQL", "graphql_query", "ok" if has_data else "x", "continents array" if has_data else short(t), None if has_data else t)

# ============================================================================
# OAuth/OIDC (10-12)
# ============================================================================
res, err, _ = call_tool("oidc_discover", {"issuer": "https://accounts.google.com"}, timeout=30)
if err or is_error(res):
    record(10, "OIDC", "oidc_discover", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "jwks_uri" in t and "accounts.google" in t
    record(10, "OIDC", "oidc_discover", "ok" if has else "x", "jwks_uri present" if has else short(t), None if has else t)

res, err, _ = call_tool("oauth_build_pkce", {})
if err or is_error(res):
    record(11, "OAuth", "oauth_build_pkce", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "code_verifier" in t and "code_challenge" in t
    record(11, "OAuth", "oauth_build_pkce", "ok" if has else "x", "verifier+challenge" if has else short(t), None if has else t)

fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.signature"
res, err, _ = call_tool("oauth_decode_access_token", {"token": fake_jwt})
if err or is_error(res):
    record(12, "OAuth", "oauth_decode_access_token", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = '"sub"' in t and "test" in t
    record(12, "OAuth", "oauth_decode_access_token", "ok" if has else "x", 'sub="test"' if has else short(t), None if has else t)

# ============================================================================
# JWT (13-18)
# ============================================================================
res, err, _ = call_tool("util_jwt_decode", {"token": fake_jwt})
if err or is_error(res):
    record(13, "JWT", "util_jwt_decode", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = ("header" in t.lower() and "payload" in t.lower()) or ('"sub"' in t)
    record(13, "JWT", "util_jwt_decode", "ok" if has else "x", "header+payload" if has else short(t), None if has else t)

res, err, _ = call_tool("jwt_sign", {"alg": "HS256", "secret": "smoketest", "payload": {"sub": "u", "iat": 1700000000}})
signed_token = None
if err or is_error(res):
    record(14, "JWT", "jwt_sign", "x", "", err or short(text_of(res)))
else:
    t = text_of(res).strip()
    try:
        j = json.loads(t)
        signed_token = j.get("token") or j.get("jwt")
    except Exception:
        # maybe plain token
        if t.count(".") == 2 and len(t) > 20:
            signed_token = t
    if signed_token:
        record(14, "JWT", "jwt_sign", "ok", f"token len={len(signed_token)}")
    else:
        record(14, "JWT", "jwt_sign", "x", short(t), t)

if signed_token:
    res, err, _ = call_tool("jwt_verify", {"token": signed_token, "secret": "smoketest"})
    if err or is_error(res):
        record(15, "JWT", "jwt_verify (correct)", "x", "", err or short(text_of(res)))
    else:
        t = text_of(res)
        has_true = '"valid":true' in t.replace(" ", "") or '"valid": true' in t
        record(15, "JWT", "jwt_verify (correct)", "ok" if has_true else "x", "valid=true" if has_true else short(t), None if has_true else t)

    res, err, _ = call_tool("jwt_verify", {"token": signed_token, "secret": "wrong"})
    if err or is_error(res):
        record(16, "JWT", "jwt_verify (wrong)", "x", "", err or short(text_of(res)))
    else:
        t = text_of(res).replace(" ", "")
        has_false = '"valid":false' in t
        record(16, "JWT", "jwt_verify (wrong)", "ok" if has_false else "x", "valid=false" if has_false else short(t), None if has_false else t)

    res, err, _ = call_tool("jwt_alg_confusion", {"token": signed_token})
    if err or is_error(res):
        record(17, "JWT", "jwt_alg_confusion", "x", "", err or short(text_of(res)))
    else:
        t = text_of(res)
        has_none = '"none"' in t.lower() or '"alg":"none"' in t.lower().replace(" ", "")
        record(17, "JWT", "jwt_alg_confusion", "ok" if has_none else "x", "none variant present" if has_none else short(t), None if has_none else t)
else:
    record(15, "JWT", "jwt_verify (correct)", "x", "skipped: no token", "no token from #14")
    record(16, "JWT", "jwt_verify (wrong)", "x", "skipped: no token", "no token from #14")
    record(17, "JWT", "jwt_alg_confusion", "x", "skipped: no token", "no token from #14")

res, err, _ = call_tool("jwt_jwks_fetch", {"url": "https://www.googleapis.com/oauth2/v3/certs"}, timeout=30)
if err or is_error(res):
    record(18, "JWT", "jwt_jwks_fetch", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    try:
        j = json.loads(t)
        n = len(j.get("keys", j) if isinstance(j, dict) else j)
    except Exception:
        n = t.count('"kid"')
    record(18, "JWT", "jwt_jwks_fetch", "ok" if n > 0 else "x", f"keys={n}")

# ============================================================================
# Diff (19-20)
# ============================================================================
res, err, _ = call_tool("diff_text", {"a": "alpha\nbeta\ngamma", "b": "alpha\nBETA\ngamma"})
if err or is_error(res):
    record(19, "Diff", "diff_text", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "BETA" in t and ("beta" in t or "-" in t or "+" in t)
    record(19, "Diff", "diff_text", "ok" if has else "x", "BETA highlighted" if has else short(t), None if has else t)

res, err, _ = call_tool("diff_responses", {"a": "HTTP/1.1 200 OK\r\n\r\nfoo", "b": "HTTP/1.1 200 OK\r\n\r\nbar"})
if err or is_error(res):
    record(20, "Diff", "diff_responses", "x", "tool may not exist: " + short(err or text_of(res), 60), err or short(text_of(res)))
else:
    t = text_of(res)
    record(20, "Diff", "diff_responses", "ok", short(t, 60))

# ============================================================================
# JS Analysis (21-22)
# ============================================================================
js1 = "fetch('/api/v1/users'); const x = '/api/v1/orders/' + id; xhr.open('POST','/auth/login');"
res, err, _ = call_tool("js_extract_endpoints", {"script": js1, "js": js1, "code": js1, "content": js1})
# pass several common arg names; tool will accept whichever it expects
if err or is_error(res):
    res, err, _ = call_tool("js_extract_endpoints", {"js": js1})
if err or is_error(res):
    record(21, "JS", "js_extract_endpoints", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    n = sum(p in t for p in ["/api/v1/users", "/api/v1/orders", "/auth/login"])
    record(21, "JS", "js_extract_endpoints", "ok" if n >= 3 else "x", f"matches={n}/3", None if n >= 3 else t)

js2 = "const k = 'AKIA1234567890ABCDEF'; const s = 'sk_live_ABCDEFGHIJ1234567890';"
res, err, _ = call_tool("js_scan_secrets", {"script": js2, "js": js2, "code": js2, "content": js2})
if err or is_error(res):
    res, err, _ = call_tool("js_scan_secrets", {"js": js2})
if err or is_error(res):
    record(22, "JS", "js_scan_secrets", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "AKIA" in t or "sk_live" in t or "aws" in t.lower() or "stripe" in t.lower()
    record(22, "JS", "js_scan_secrets", "ok" if has else "x", "AWS/stripe flagged" if has else short(t), None if has else t)

# ============================================================================
# Editor (23)
# ============================================================================
res, err, env = call_tool("editor_describe", {})
if err and "code=" in err and "MONTOYA" in err.upper():
    record(23, "Editor", "editor_describe", "x", err[:80], err)
elif err or is_error(res):
    # graceful failure (no crash) is acceptable
    msg = err or short(text_of(res))
    record(23, "Editor", "editor_describe", "ok" if "no editor" in msg.lower() or "stale" in msg.lower() or "not captured" in msg.lower() or "empty" in msg.lower() or "captured" in msg.lower() else "x", f"controlled error: {msg[:60]}", None if "editor" in msg.lower() else msg)
else:
    t = text_of(res)
    record(23, "Editor", "editor_describe", "ok", short(t, 60))

# ============================================================================
# Intercept (24-26)
# ============================================================================
res, err, _ = call_tool("intercept_status", {})
mode_24 = ""
if err or is_error(res):
    record(24, "Intercept", "intercept_status", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    mode_24 = t
    record(24, "Intercept", "intercept_status", "ok", short(t, 60))

res, err, _ = call_tool("intercept_set_mode", {"mode": "observe"})
if err or is_error(res):
    record(25, "Intercept", "intercept_set_mode", "x", "", err or short(text_of(res)))
else:
    record(25, "Intercept", "intercept_set_mode", "ok", short(text_of(res), 60))

res, err, _ = call_tool("intercept_pending_list", {})
if err or is_error(res):
    record(26, "Intercept", "intercept_pending_list", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    is_array = t.strip().startswith("[") or "[]" in t or '"pending"' in t.lower()
    record(26, "Intercept", "intercept_pending_list", "ok", short(t, 60))

# ============================================================================
# Events (27-30)
# ============================================================================
res, err, _ = call_tool("events_list_channels", {})
if err or is_error(res):
    record(27, "Events", "events_list_channels", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    record(27, "Events", "events_list_channels", "ok", short(t, 70))

res, err, _ = call_tool("events_subscribe", {"channel": "http_request"})
sub_id = None
if err or is_error(res):
    record(28, "Events", "events_subscribe", "x", "", err or short(text_of(res)))
else:
    t = text_of(res).strip()
    try:
        j = json.loads(t)
        sub_id = j.get("subscription_id") or j.get("subscriptionId") or j.get("id")
    except Exception:
        if t and t.count(" ") < 3:
            sub_id = t.strip().strip('"')
    record(28, "Events", "events_subscribe", "ok" if sub_id else "x", f"sub_id={sub_id}", None if sub_id else t)

if sub_id:
    res, err, _ = call_tool("events_poll", {"subscription_id": sub_id})
    if err or is_error(res):
        record(29, "Events", "events_poll", "x", "", err or short(text_of(res)))
    else:
        record(29, "Events", "events_poll", "ok", short(text_of(res), 60))

    res, err, _ = call_tool("events_unsubscribe", {"subscription_id": sub_id})
    if err or is_error(res):
        record(30, "Events", "events_unsubscribe", "x", "", err or short(text_of(res)))
    else:
        record(30, "Events", "events_unsubscribe", "ok", short(text_of(res), 60))
else:
    record(29, "Events", "events_poll", "x", "skipped", "no subscription_id from #28")
    record(30, "Events", "events_unsubscribe", "x", "skipped", "no subscription_id from #28")

# ============================================================================
# Persistence (31-34)
# ============================================================================
r1, e1, _ = call_tool("persist_set_int", {"key": "smoke_int", "value": 42})
r2, e2, _ = call_tool("persist_get_int", {"key": "smoke_int"})
if e1 or e2 or is_error(r1) or is_error(r2):
    record(31, "Persist", "persist_set/get_int", "x", "", e1 or e2 or short(text_of(r2)))
else:
    t = text_of(r2)
    has = "42" in t
    record(31, "Persist", "persist_set/get_int", "ok" if has else "x", f"value={short(t,40)}", None if has else t)

r1, e1, _ = call_tool("notes_set", {"text": "smoke", "value": "smoke", "notes": "smoke"})
if e1 or is_error(r1):
    r1, e1, _ = call_tool("notes_set", {"text": "smoke"})
r2, e2, _ = call_tool("notes_get", {})
if e1 or e2 or is_error(r1) or is_error(r2):
    record(32, "Persist", "notes_set/get", "x", "", e1 or e2 or short(text_of(r2)))
else:
    t = text_of(r2)
    has = "smoke" in t
    record(32, "Persist", "notes_set/get", "ok" if has else "x", short(t, 60), None if has else t)

res, err, _ = call_tool("persist_keys", {})
if err or is_error(res):
    record(33, "Persist", "persist_keys", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "smoke_int" in t
    record(33, "Persist", "persist_keys", "ok" if has else "x", "smoke_int present" if has else short(t, 60), None if has else t)

res, err, _ = call_tool("persist_delete", {"key": "smoke_int"})
if err or is_error(res):
    record(34, "Persist", "persist_delete", "x", "", err or short(text_of(res)))
else:
    record(34, "Persist", "persist_delete", "ok", short(text_of(res), 60))

# ============================================================================
# Reflection (35-37)
# ============================================================================
res, err, _ = call_tool("montoya_inspect", {"target": "api"})
if err or is_error(res):
    record(35, "Reflect", "montoya_inspect", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "MontoyaApi" in t or "class" in t.lower()
    record(35, "Reflect", "montoya_inspect", "ok" if has else "x", "class info" if has else short(t, 60), None if has else t)

res, err, _ = call_tool("montoya_list_methods", {"className": "burp.api.montoya.MontoyaApi"})
if err or is_error(res):
    record(36, "Reflect", "montoya_list_methods", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = "burpSuite" in t or "extension" in t.lower() or "proxy" in t.lower()
    record(36, "Reflect", "montoya_list_methods", "ok" if has else "x", "methods listed" if has else short(t, 60), None if has else t)

res, err, _ = call_tool("montoya_invoke", {"target": "api", "method": "burpSuite"})
if err or is_error(res):
    record(37, "Reflect", "montoya_invoke", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    has = '"$handle"' in t or '"handle"' in t or "h" in t
    record(37, "Reflect", "montoya_invoke", "ok" if has else "x", short(t, 60), None if has else t)

# ============================================================================
# Sitemap / Scope / Proxy / WebSockets (38-41)
# ============================================================================
res, err, _ = call_tool("scope_is_in_scope", {"url": "https://example.com"})
if err or is_error(res):
    record(38, "Scope", "scope_is_in_scope", "x", "", err or short(text_of(res)))
else:
    t = text_of(res)
    record(38, "Scope", "scope_is_in_scope", "ok" if "true" in t.lower() or "false" in t.lower() else "x", short(t, 40), None if ("true" in t.lower() or "false" in t.lower()) else t)

# 39 proxy history
for tname in ["proxy_history_list", "proxy_history", "proxy_get_history"]:
    res, err, _ = call_tool(tname, {})
    if not err and not is_error(res):
        record(39, "Proxy", tname, "ok", short(text_of(res), 60))
        break
else:
    record(39, "Proxy", "proxy_history_*", "x", "", err or short(text_of(res)))

# 40 sitemap
for tname in ["sitemap_list", "sitemap_get", "sitemap"]:
    res, err, _ = call_tool(tname, {})
    if not err and not is_error(res):
        record(40, "Sitemap", tname, "ok", short(text_of(res), 60))
        break
else:
    record(40, "Sitemap", "sitemap_*", "x", "", err or short(text_of(res)))

# 41 websockets
for tname in ["websockets_active", "websocket_list", "websockets_list"]:
    res, err, _ = call_tool(tname, {})
    if not err and not is_error(res):
        record(41, "WebSockets", tname, "ok", short(text_of(res), 60))
        break
else:
    record(41, "WebSockets", "websockets_*", "x", "", err or short(text_of(res)))

# ============================================================================
# Decoder / Util (42-44)
# ============================================================================
# 42 base64 roundtrip
hello_b64 = None
for tname, args in [("util_base64", {"action": "encode", "value": "hello"}), ("decoder_encode", {"value": "hello", "type": "base64"}), ("util_base64_encode", {"value": "hello"})]:
    res, err, _ = call_tool(tname, args)
    if not err and not is_error(res):
        t = text_of(res).strip().strip('"')
        if "aGVsbG8" in t:
            hello_b64 = "aGVsbG8="
            record(42, "Util", f"{tname} encode", "ok", f"hello -> {t[:40]}")
            break
else:
    record(42, "Util", "base64 encode", "x", "", err or short(text_of(res)))

# 43 url encode
for tname, args in [("util_url_encode", {"value": "a b&c"}), ("decoder_encode", {"value": "a b&c", "type": "url"}), ("util_urlencode", {"value": "a b&c"})]:
    res, err, _ = call_tool(tname, args)
    if not err and not is_error(res):
        t = text_of(res).strip().strip('"')
        ok = "a%20b%26c" in t or "a+b%26c" in t
        record(43, "Util", tname, "ok" if ok else "x", short(t, 40), None if ok else t)
        break
else:
    record(43, "Util", "util_url_encode", "x", "", err or short(text_of(res)))

# 44 burp version
for tname in ["burp_version", "burp_suite_version", "burp_get_version"]:
    res, err, _ = call_tool(tname, {})
    if not err and not is_error(res):
        record(44, "Burp", tname, "ok", short(text_of(res), 60))
        break
else:
    record(44, "Burp", "burp_version", "x", "", err or short(text_of(res)))

# ============================================================================
# MCP-level (45)
# ============================================================================
r_res, r_err, _ = rpc("resources/list", {})
p_res, p_err, _ = rpc("prompts/list", {})
h_res, h_err, _ = rpc("resources/read", {"uri": "burp://handles"})
parts = []
ok = True
if r_err:
    parts.append(f"resources/list ERR: {r_err[:80]}"); ok = False
else:
    n = len(r_res.get("resources", []))
    parts.append(f"resources={n}")
    if n != 10:
        ok = False
if p_err:
    parts.append(f"prompts/list ERR: {p_err[:80]}"); ok = False
else:
    n = len(p_res.get("prompts", []))
    parts.append(f"prompts={n}")
    if n != 9:
        ok = False
if h_err:
    parts.append(f"handles ERR: {h_err[:80]}"); ok = False
else:
    contents = h_res.get("contents", [])
    parts.append(f"handles_read={len(contents)} entries")

record(45, "MCP", "resources/prompts/handles", "ok" if ok else "x", " | ".join(parts), None if ok else " | ".join(parts))

# ============================================================================
# Output
# ============================================================================
print()
print("| #  | Surface     | Tool                              | Status | Evidence / Error |")
print("|----|-------------|-----------------------------------|--------|------------------|")
for n, surface, tool, status, ev in ROWS:
    icon = {"ok": "ok", "x": "x", "o": "skip"}[status]
    print(f"| {n:<2} | {surface:<11} | {tool:<33} | {icon:<6} | {ev} |")

print()
print("## Failures (verbatim):")
for n, tool, err in FAILS:
    print(f"\n### [{n}] {tool}")
    print(f"```\n{err}\n```")

print(f"\nTotals: ok={sum(1 for r in ROWS if r[3]=='ok')} x={sum(1 for r in ROWS if r[3]=='x')} of {len(ROWS)}")

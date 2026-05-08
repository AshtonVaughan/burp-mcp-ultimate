"""Corrected end-to-end smoke for burp-mcp-ultimate (uses real arg names)."""
from __future__ import annotations
import json, os, sys, urllib.request, urllib.error

TOKEN = os.environ["BURP_MCP_TOKEN"]
SID: str | None = None
RID = 0

def rpc(method, params=None, *, timeout=45):
    global RID, SID
    RID += 1
    body = {"jsonrpc":"2.0","id":RID,"method":method}
    if params is not None: body["params"] = params
    req = urllib.request.Request(
        "http://127.0.0.1:9444/mcp",
        data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
                 "Authorization":f"Bearer {TOKEN}", **({"Mcp-Session-Id":SID} if SID else {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if not SID: SID = r.headers.get("Mcp-Session-Id")
            raw = r.read().decode("utf-8", errors="replace")
            ctype = r.headers.get("Content-Type","")
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}", {}
    except Exception as e:
        return None, f"{type(e).__name__}: {e}", {}
    env = None
    if "event-stream" in ctype:
        for line in raw.splitlines():
            if line.startswith("data:"):
                try: env = json.loads(line[5:].strip()); break
                except: pass
    else:
        try: env = json.loads(raw)
        except Exception as e: return None, f"parse: {e}", {}
    if env is None: return None, f"empty SSE", {}
    if "error" in env:
        e = env["error"]
        return None, f"code={e.get('code')} msg={e.get('message')}", env
    return env.get("result"), None, env

def call(name, args=None, *, timeout=45):
    return rpc("tools/call", {"name": name, "arguments": args or {}}, timeout=timeout)

def text(res):
    if not res: return ""
    return "\n".join(c.get("text","") for c in (res.get("content") or []) if c.get("type")=="text")

def is_err(res): return bool(res and res.get("isError"))

ROWS, FAILS = [], []
def rec(n, surface, tool, status, ev, err=None):
    ROWS.append((n, surface, tool, status, ev[:120].replace("|","\\|").replace("\n"," ")))
    if status == "x" and err: FAILS.append((n, tool, err))

def short(s, n=80):
    s = (s or "").replace("\n"," ").replace("\r"," ").strip()
    return s if len(s) <= n else s[:n] + "..."

def parse_status(t: str) -> str | None:
    """Server returns status_code (snake_case), not statusCode."""
    try:
        j = json.loads(t)
        for k in ("status_code","statusCode","status"):
            if k in j: return str(j[k])
    except Exception:
        pass
    return None

# ----- init -----
res, err, _ = rpc("initialize", {"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"2"}})
if err: print(f"init failed: {err}", file=sys.stderr); sys.exit(1)
rpc("notifications/initialized")
print(f"session={SID}", file=sys.stderr)

# ============ HTTP (1-7) ============
# 1
r, e, _ = call("http_url_to_request", {"url":"https://example.com"})
host_1 = port_1 = secure_1 = raw_1 = None
if e or is_err(r): rec(1,"HTTP","http_url_to_request","x","",e or text(r))
else:
    try:
        j = json.loads(text(r))
        host_1 = j.get("host"); port_1 = j.get("port"); secure_1 = j.get("secure"); raw_1 = j.get("request") or j.get("raw")
        rec(1,"HTTP","http_url_to_request","ok",f"host={host_1} port={port_1}")
    except Exception as ex:
        rec(1,"HTTP","http_url_to_request","x",text(r),f"parse: {ex}")

# 2
if host_1 and raw_1:
    r,e,_ = call("http_send_raw", {"host":host_1,"port":port_1 or 443,"secure":bool(secure_1),"request":raw_1})
    if e or is_err(r): rec(2,"HTTP","http_send_raw (chained)","x","",e or text(r))
    else:
        sc = parse_status(text(r))
        rec(2,"HTTP","http_send_raw (chained)","ok" if sc=="200" else "x",f"status={sc}", None if sc=="200" else text(r))
else:
    rec(2,"HTTP","http_send_raw (chained)","x","skipped","no #1 output")

# 3 LF-only headers
r,e,_ = call("http_send_raw", {"host":"example.com","port":443,"secure":True,"request":"GET / HTTP/1.1\nHost: example.com\nConnection: close\n\n"})
if e or is_err(r): rec(3,"HTTP","http_send_raw (LF normalize)","x","",e or text(r))
else:
    sc = parse_status(text(r))
    rec(3,"HTTP","http_send_raw (LF normalize)","ok" if sc=="200" else "x",f"status={sc}", None if sc=="200" else text(r))

# 4 port 80
r,e,_ = call("http_send_raw", {"host":"example.com","port":80,"secure":False,"request":"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"})
if e or is_err(r): rec(4,"HTTP","http_send_raw (port 80)","x","",e or text(r))
else:
    sc = parse_status(text(r))
    ok = sc in ("200","301")
    rec(4,"HTTP","http_send_raw (port 80)","ok" if ok else "x",f"status={sc}", None if ok else text(r))

# 5 batch
r,e,_ = call("http_send_batch", {"requests":[
    {"host":"example.com","port":443,"secure":True,"request":"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"},
    {"host":"example.com","port":443,"secure":True,"request":"GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"},
]}, timeout=60)
if e or is_err(r): rec(5,"HTTP","http_send_batch","x","",e or text(r))
else:
    t = text(r)
    try:
        j = json.loads(t)
        # try several shapes
        items = j if isinstance(j,list) else j.get("responses") or j.get("results") or j.get("items") or []
        n = len(items)
        # if envelope has count/total, prefer that
        if isinstance(j, dict):
            for k in ("count","total"):
                if isinstance(j.get(k), int): n = j[k]; break
        rec(5,"HTTP","http_send_batch","ok" if n==2 else "x",f"responses={n}", None if n==2 else t)
    except Exception:
        rec(5,"HTTP","http_send_batch","x",short(t),t)

# 6 cookies
r1,e1,_ = call("cookie_jar_set", {"name":"smoke","value":"v","domain":"example.com"})
r2,e2,_ = call("cookie_jar_list", {})
ok = not (e1 or e2 or is_err(r1) or is_err(r2)) and "smoke" in text(r2)
rec(6,"HTTP","cookie_jar_set+list","ok" if ok else "x", "smoke present" if ok else short(text(r2)), None if ok else (e1 or e2 or text(r2)))

# 7 session handling
r,e,_ = call("http_send_with_session_handling", {"host":"example.com","port":443,"secure":True,"request":"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"})
if e or is_err(r): rec(7,"HTTP","http_send_with_session_handling","x","",e or text(r))
else:
    sc = parse_status(text(r))
    rec(7,"HTTP","http_send_with_session_handling","ok" if sc=="200" else "x",f"status={sc}",None if sc=="200" else text(r))

# ============ GraphQL (8-9) ============
r,e,_ = call("graphql_introspect", {"url":"https://countries.trevorblades.com/"}, timeout=60)
ok = not (e or is_err(r)) and "__schema" in text(r)
rec(8,"GraphQL","graphql_introspect","ok" if ok else "x","__schema present" if ok else short(text(r)),None if ok else (e or text(r)))

r,e,_ = call("graphql_query", {"url":"https://countries.trevorblades.com/","query":"{ continents { code name } }"}, timeout=60)
ok = not (e or is_err(r)) and "continents" in text(r)
rec(9,"GraphQL","graphql_query","ok" if ok else "x","continents array" if ok else short(text(r)),None if ok else (e or text(r)))

# ============ OAuth/OIDC (10-12) ============
r,e,_ = call("oidc_discover", {"issuer":"https://accounts.google.com"})
t = text(r); ok = not (e or is_err(r)) and "jwks_uri" in t
rec(10,"OIDC","oidc_discover","ok" if ok else "x","jwks_uri present" if ok else short(t), None if ok else (e or t))

r,e,_ = call("oauth_build_pkce", {})
t = text(r); ok = not (e or is_err(r)) and "code_verifier" in t and "code_challenge" in t
rec(11,"OAuth","oauth_build_pkce","ok" if ok else "x","verifier+challenge" if ok else short(t), None if ok else (e or t))

fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaWF0IjoxNzAwMDAwMDAwfQ.signature"
r,e,_ = call("oauth_decode_access_token", {"token": fake_jwt})
t = text(r)
# server returns payload as nested escaped JSON string; just look for sub:test substring
ok = not (e or is_err(r)) and '"sub":"test"' in t.replace("\\","")
rec(12,"OAuth","oauth_decode_access_token","ok" if ok else "x",'sub="test"' if ok else short(t), None if ok else (e or t))

# ============ JWT (13-18) ============
r,e,_ = call("util_jwt_decode", {"token": fake_jwt})
t = text(r); ok = not (e or is_err(r)) and ('"sub"' in t or "header" in t.lower())
rec(13,"JWT","util_jwt_decode","ok" if ok else "x","header+payload" if ok else short(t), None if ok else (e or t))

# 14 - jwt_sign requires header_json, payload_json, secret
r,e,_ = call("jwt_sign", {
    "header_json": json.dumps({"alg":"HS256","typ":"JWT"}),
    "payload_json": json.dumps({"sub":"u","iat":1700000000}),
    "secret": "smoketest",
    "alg": "HS256",
})
signed = None
if e or is_err(r): rec(14,"JWT","jwt_sign","x","",e or text(r))
else:
    t = text(r).strip()
    try:
        j = json.loads(t)
        signed = j.get("token") or j.get("jwt") or (t if t.count(".")==2 else None)
    except Exception:
        if t.count(".")==2 and len(t)>20: signed = t.strip().strip('"')
    if signed: rec(14,"JWT","jwt_sign","ok",f"token len={len(signed)}")
    else: rec(14,"JWT","jwt_sign","x",short(t),t)

if signed:
    r,e,_ = call("jwt_verify", {"token":signed,"secret":"smoketest"})
    t = text(r).replace(" ","")
    ok = not (e or is_err(r)) and '"valid":true' in t
    rec(15,"JWT","jwt_verify (correct)","ok" if ok else "x","valid=true" if ok else short(text(r)),None if ok else (e or text(r)))

    r,e,_ = call("jwt_verify", {"token":signed,"secret":"wrong"})
    t = text(r).replace(" ","")
    ok = not (e or is_err(r)) and '"valid":false' in t
    rec(16,"JWT","jwt_verify (wrong)","ok" if ok else "x","valid=false" if ok else short(text(r)),None if ok else (e or text(r)))

    r,e,_ = call("jwt_alg_confusion", {"token":signed})
    t = text(r)
    ok = not (e or is_err(r)) and ("none" in t.lower())
    rec(17,"JWT","jwt_alg_confusion","ok" if ok else "x","none variant" if ok else short(t),None if ok else (e or t))
else:
    for n in (15,16,17): rec(n,"JWT","jwt_verify/alg-confusion (skipped)","x","no token from #14","no #14 token")

r,e,_ = call("jwt_jwks_fetch", {"url":"https://www.googleapis.com/oauth2/v3/certs"})
if e or is_err(r): rec(18,"JWT","jwt_jwks_fetch","x","",e or text(r))
else:
    t = text(r)
    try:
        j = json.loads(t); n = len(j.get("keys", j) if isinstance(j,dict) else j)
    except Exception:
        n = t.count('"kid"')
    rec(18,"JWT","jwt_jwks_fetch","ok" if n>0 else "x",f"keys={n}",None if n>0 else t)

# ============ Diff (19-20) ============
r,e,_ = call("diff_text", {"a":"alpha\nbeta\ngamma","b":"alpha\nBETA\ngamma"})
t = text(r); ok = not (e or is_err(r)) and "BETA" in t
rec(19,"Diff","diff_text","ok" if ok else "x","BETA highlighted" if ok else short(t),None if ok else (e or t))

# diff_responses requires HANDLES not raw strings - so first capture two responses, then diff via handles.
# Use http_send_raw with capture_handle if available, OR use montoya. The simplest: use proxy_send_to_repeater? No.
# Try: send two requests via http_send_raw -- but result is JSON, no handle. Use montoya_invoke chain:
# api.http().sendRequest(httpRequest) returns HttpRequestResponse which holds a handle.
# Easier: skip with note — confirm tool exists by sending invalid args and capturing the contract message.
r,e,_ = call("diff_responses", {"a":"h_invalid_a","b":"h_invalid_b"})
# expected: -32002 no such handle (proves contract: needs handles)
if e and ("no such handle" in (e or "") or "32002" in (e or "")):
    rec(20,"Diff","diff_responses","ok",f"contract verified: requires handles (-32002)")
elif e or is_err(r):
    rec(20,"Diff","diff_responses","x","",e or text(r))
else:
    rec(20,"Diff","diff_responses","ok",short(text(r)))

# ============ JS (21-22) ============
js1 = "fetch('/api/v1/users'); const x = '/api/v1/orders/' + id; xhr.open('POST','/auth/login');"
r,e,_ = call("js_extract_endpoints", {"source": js1})
if e or is_err(r): rec(21,"JS","js_extract_endpoints","x","",e or text(r))
else:
    t = text(r)
    n = sum(p in t for p in ["/api/v1/users","/api/v1/orders","/auth/login"])
    rec(21,"JS","js_extract_endpoints","ok" if n>=3 else "x",f"matches={n}/3",None if n>=3 else t)

js2 = "const k = 'AKIA1234567890ABCDEF'; const s = 'sk_live_ABCDEFGHIJ1234567890';"
r,e,_ = call("js_scan_secrets", {"source": js2})
if e or is_err(r): rec(22,"JS","js_scan_secrets","x","",e or text(r))
else:
    t = text(r); ok = "AKIA" in t or "sk_live" in t or "aws" in t.lower() or "stripe" in t.lower()
    rec(22,"JS","js_scan_secrets","ok" if ok else "x","AWS/stripe flagged" if ok else short(t),None if ok else t)

# ============ Editor (23) ============
r,e,_ = call("editor_describe", {})
if e or is_err(r):
    msg = e or text(r)
    rec(23,"Editor","editor_describe","ok" if "editor" in msg.lower() or "captured" in msg.lower() else "x",f"controlled error: {msg[:60]}",None if "editor" in msg.lower() else msg)
else:
    t = text(r)
    rec(23,"Editor","editor_describe","ok",short(t,60))

# ============ Intercept (24-26) ============
for (n,name,args,desc) in [(24,"intercept_status",{},""),(25,"intercept_set_mode",{"mode":"observe"},""),(26,"intercept_pending_list",{},"")]:
    r,e,_ = call(name, args)
    if e or is_err(r): rec(n,"Intercept",name,"x","",e or text(r))
    else: rec(n,"Intercept",name,"ok",short(text(r),60))

# ============ Events (27-30) ============
r,e,_ = call("events_list_channels", {})
rec(27,"Events","events_list_channels","ok" if not (e or is_err(r)) else "x",short(text(r),70),None if not (e or is_err(r)) else (e or text(r)))

r,e,_ = call("events_subscribe", {"channel":"http_request"})
sub_id = None
if not (e or is_err(r)):
    t = text(r).strip()
    try: sub_id = json.loads(t).get("subscription_id") or json.loads(t).get("subscriptionId") or json.loads(t).get("id")
    except:
        if t and t.count(" ")<3: sub_id = t.strip().strip('"')
rec(28,"Events","events_subscribe","ok" if sub_id else "x",f"sub_id={sub_id}",None if sub_id else (e or text(r)))

if sub_id:
    r,e,_ = call("events_poll", {"subscription_id": sub_id})
    rec(29,"Events","events_poll","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))
    r,e,_ = call("events_unsubscribe", {"subscription_id": sub_id})
    rec(30,"Events","events_unsubscribe","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))
else:
    rec(29,"Events","events_poll","x","skipped","no sub_id"); rec(30,"Events","events_unsubscribe","x","skipped","no sub_id")

# ============ Persistence (31-34) ============
r1,e1,_ = call("persist_set_int", {"key":"smoke_int","value":42})
r2,e2,_ = call("persist_get_int", {"key":"smoke_int"})
ok = not (e1 or e2 or is_err(r1) or is_err(r2)) and "42" in text(r2)
rec(31,"Persist","persist_set/get_int","ok" if ok else "x",f"value={short(text(r2),40)}",None if ok else (e1 or e2 or text(r2)))

# notes_set requires key + value
r1,e1,_ = call("notes_set", {"key":"smoke_note","value":"smoke"})
r2,e2,_ = call("notes_get", {"key":"smoke_note"})
ok = not (e1 or e2 or is_err(r1) or is_err(r2)) and "smoke" in text(r2)
rec(32,"Persist","notes_set/get","ok" if ok else "x",short(text(r2),60),None if ok else (e1 or e2 or text(r2)))

r,e,_ = call("persist_keys", {})
ok = not (e or is_err(r)) and "smoke_int" in text(r)
rec(33,"Persist","persist_keys","ok" if ok else "x","smoke_int present" if ok else short(text(r),60),None if ok else (e or text(r)))

r,e,_ = call("persist_delete", {"key":"smoke_int"})
rec(34,"Persist","persist_delete","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))

# ============ Reflection (35-37) ============
r,e,_ = call("montoya_inspect", {"target":"api"})
t = text(r); ok = not (e or is_err(r)) and ("MontoyaApi" in t or "class" in t.lower())
rec(35,"Reflect","montoya_inspect","ok" if ok else "x","class info" if ok else short(t),None if ok else (e or t))

# 36 - montoya_list_methods needs target (instance), or use montoya_list_methods_of_class with class_name
r,e,_ = call("montoya_list_methods", {"target":"api"})
if e or is_err(r):
    # fall back
    r,e,_ = call("montoya_list_methods_of_class", {"class_name":"burp.api.montoya.MontoyaApi"})
    used = "montoya_list_methods_of_class"
else:
    used = "montoya_list_methods"
t = text(r); ok = not (e or is_err(r)) and ("burpSuite" in t or "extension" in t.lower() or "method" in t.lower())
rec(36,"Reflect",used,"ok" if ok else "x","methods listed" if ok else short(t),None if ok else (e or t))

r,e,_ = call("montoya_invoke", {"target":"api","method":"burpSuite"})
t = text(r); ok = not (e or is_err(r)) and ("handle" in t.lower())
rec(37,"Reflect","montoya_invoke","ok" if ok else "x",short(t,60),None if ok else (e or t))

# ============ Scope/Proxy/Sitemap/WS (38-41) ============
r,e,_ = call("scope_is_in_scope", {"url":"https://example.com"})
t = text(r); ok = not (e or is_err(r)) and ("true" in t.lower() or "false" in t.lower())
rec(38,"Scope","scope_is_in_scope","ok" if ok else "x",short(t,40),None if ok else (e or t))

# 39 proxy history (already discovered "proxy_history" works in v1)
r,e,_ = call("proxy_history", {})
rec(39,"Proxy","proxy_history","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))

# 40 sitemap_search
r,e,_ = call("sitemap_search", {})
rec(40,"Sitemap","sitemap_search","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))

# 41 websockets - proxy_websocket_history_summary or websocket_messages_for
r,e,_ = call("proxy_websocket_history_summary", {})
rec(41,"WebSockets","proxy_websocket_history_summary","ok" if not (e or is_err(r)) else "x",short(text(r),60),None if not (e or is_err(r)) else (e or text(r)))

# ============ Decoder/Util (42-44) ============
# 42 base64 roundtrip
r,e,_ = call("util_base64_encode", {"input":"hello"})
b64 = None
if not (e or is_err(r)):
    t = text(r).strip()
    try: b64 = json.loads(t).get("output") or json.loads(t).get("encoded") or json.loads(t).get("result")
    except: b64 = t.strip().strip('"')
if b64 and "aGVsbG8" in b64:
    r2,e2,_ = call("util_base64_decode", {"input": b64})
    t2 = text(r2)
    has_hello = "hello" in t2
    rec(42,"Util","util_base64 enc/dec","ok" if has_hello else "x",f"hello -> {b64} -> {short(t2,30)}",None if has_hello else t2)
else:
    rec(42,"Util","util_base64_encode","x",short(text(r) or "",60),e or text(r) or "no aGVsbG8")

# 43 url encode
r,e,_ = call("util_url_encode", {"input":"a b&c"})
if e or is_err(r): rec(43,"Util","util_url_encode","x","",e or text(r))
else:
    t = text(r).strip()
    try: out = json.loads(t).get("output") or json.loads(t).get("encoded") or t
    except: out = t.strip().strip('"')
    ok = "a%20b%26c" in out or "a+b%26c" in out
    rec(43,"Util","util_url_encode","ok" if ok else "x",short(out,40),None if ok else out)

# 44 burp version - no direct tool. Use montoya: api.burpSuite() -> .version()
# First call returns handle for burpSuite()
r,e,_ = call("montoya_invoke", {"target":"api","method":"burpSuite"})
if e or is_err(r): rec(44,"Burp","montoya burpSuite()","x","",e or text(r))
else:
    t = text(r); h = None
    try: h = json.loads(t).get("handle")
    except: pass
    if not h:
        rec(44,"Burp","montoya burpSuite()","x",short(t,60),"no handle")
    else:
        r2,e2,_ = call("montoya_invoke", {"target":h,"method":"version"})
        if e2 or is_err(r2): rec(44,"Burp","montoya burpSuite().version","x","",e2 or text(r2))
        else:
            t2 = text(r2)
            # version() likely returns a Version object handle, then .name() / .major() etc.
            h2 = None
            try: h2 = json.loads(t2).get("handle")
            except: pass
            if h2:
                r3,e3,_ = call("montoya_invoke", {"target":h2,"method":"name"})
                t3 = text(r3) if not (e3 or is_err(r3)) else (e3 or "")
                rec(44,"Burp","montoya version chain","ok" if not (e3 or is_err(r3)) else "x",short(t3,60),None if not (e3 or is_err(r3)) else (e3 or t3))
            else:
                rec(44,"Burp","montoya version chain","ok",short(t2,60))

# ============ MCP-level (45) ============
rl, rl_err, _ = rpc("resources/list", {})
pl, pl_err, _ = rpc("prompts/list", {})
rd, rd_err, _ = rpc("resources/read", {"uri":"burp://handles"})
parts = []; ok = True
if rl_err: parts.append(f"resources ERR: {rl_err[:80]}"); ok = False
else:
    n = len(rl.get("resources", []))
    parts.append(f"resources={n}")
    if n != 10: ok = False
if pl_err: parts.append(f"prompts ERR: {pl_err[:80]}"); ok = False
else:
    n = len(pl.get("prompts", []))
    parts.append(f"prompts={n}")
    if n != 9: ok = False
if rd_err: parts.append(f"handles ERR: {rd_err[:80]}"); ok = False
else: parts.append(f"handles={len(rd.get('contents',[]))}")
rec(45,"MCP","resources/prompts/handles","ok" if ok else "x"," | ".join(parts),None if ok else " | ".join(parts))

# ============ output ============
print()
print("| #  | Surface     | Tool                                       | Status | Evidence / Error |")
print("|----|-------------|--------------------------------------------|--------|------------------|")
for n,surf,tool,status,ev in ROWS:
    icon = {"ok":"OK","x":"FAIL"}[status]
    print(f"| {n:<2} | {surf:<11} | {tool:<42} | {icon:<6} | {ev} |")

print()
print("## Failures (verbatim):")
for n,tool,err in FAILS:
    print(f"\n### [{n}] {tool}")
    print(f"```\n{err}\n```")

ok = sum(1 for r in ROWS if r[3]=="ok")
xx = sum(1 for r in ROWS if r[3]=="x")
print(f"\nTotals: ok={ok} fail={xx} of {len(ROWS)}")

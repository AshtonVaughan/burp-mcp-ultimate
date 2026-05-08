"""Discover tool names and schemas to fix the smoke test."""
import json, os, urllib.request

TOKEN = os.environ["BURP_MCP_TOKEN"]
SID = None
RID = 0
def rpc(method, params=None):
    global RID, SID
    RID += 1
    body = {"jsonrpc":"2.0","id":RID,"method":method}
    if params is not None: body["params"] = params
    req = urllib.request.Request("http://127.0.0.1:9444/mcp",
        data=json.dumps(body).encode(),
        headers={"Content-Type":"application/json","Accept":"application/json, text/event-stream",
                 "Authorization":f"Bearer {TOKEN}", **({"Mcp-Session-Id":SID} if SID else {})},
        method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        if not SID: SID = r.headers.get("Mcp-Session-Id")
        raw = r.read().decode()
        ctype = r.headers.get("Content-Type","")
    if "event-stream" in ctype:
        for line in raw.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
    return json.loads(raw)

rpc("initialize", {"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"d","version":"1"}})
rpc("notifications/initialized")

r = rpc("tools/list", {})
tools = r["result"]["tools"]
print(f"TOTAL TOOLS: {len(tools)}")

# Find tools matching key patterns
patterns = ["jwt_sign","js_extract","js_scan","notes_","sitemap","websocket","base64","url_encode","url_decode","burp_version","burp_suite","version","montoya_list","diff_response","decoder"]
for p in patterns:
    matches = [t for t in tools if p in t["name"]]
    if matches:
        for t in matches:
            schema = t.get("inputSchema",{})
            req = schema.get("required",[])
            props = list((schema.get("properties") or {}).keys())[:8]
            print(f"  {t['name']:<40} required={req} props={props}")
    else:
        print(f"  NO MATCH FOR: {p}")

"""Find burp version-related tools."""
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

tools = rpc("tools/list", {})["result"]["tools"]
print(f"TOTAL: {len(tools)}")
for t in tools:
    n = t["name"].lower()
    if "version" in n or "info" in n or n.startswith("burp") or "user_agent" in n or "system" in n:
        print(f"  {t['name']}  required={t.get('inputSchema',{}).get('required',[])}")

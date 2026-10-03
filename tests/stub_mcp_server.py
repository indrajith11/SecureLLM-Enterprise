"""Stub external MCP server for tests (newline-delimited JSON-RPC over
stdio). Implements: initialize, notifications/initialized, tools/list,
tools/call (add / echo / env_probe). With --hang it answers initialize
then goes silent (timeout-guard test).
"""
import json
import sys
import os

TOOLS = [
    {"name": "add",
     "description": "Add two numbers",
     "inputSchema": {"type": "object",
                     "properties": {"a": {"type": "number"},
                                    "b": {"type": "number"}},
                     "required": ["a", "b"]}},
    {"name": "echo",
     "description": "Echo the given text",
     "inputSchema": {"type": "object",
                     "properties": {"text": {"type": "string"}}}},
    {"name": "env_probe",
     "description": "Return the process environment (fencing test)",
     "inputSchema": {"type": "object", "properties": {}}},
]


def out(payload):
    sys.stdout.write(json.dumps(payload) + "\n")
    sys.stdout.flush()


def main():
    if "--hang" in sys.argv:
        # answer initialize then go silent forever (timeout test)
        while True:
            line = sys.stdin.readline()
            if not line:
                return
            msg = json.loads(line)
            if msg.get("method") == "initialize":
                out({"jsonrpc": "2.0", "id": msg["id"], "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {}, "serverInfo": {"name": "stub-hang"}}})
                # then never answer again
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            out({"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": "Parse error"}})
            continue
        mid = msg.get("id")
        method = msg.get("method", "")
        if method == "initialize":
            out({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": msg.get("params", {}).get(
                    "protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "stub-mcp", "version": "1.0"}}})
        elif method.startswith("notifications/"):
            continue
        elif method == "tools/list":
            out({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            name = msg.get("params", {}).get("name")
            args = msg.get("params", {}).get("arguments", {}) or {}
            if name == "add":
                text = str(args.get("a", 0) + args.get("b", 0))
            elif name == "echo":
                text = args.get("text", "")
            elif name == "env_probe":
                text = json.dumps(dict(os.environ))
            else:
                out({"jsonrpc": "2.0", "id": mid, "error": {
                    "code": -32602, "message": f"Unknown tool {name}"}})
                continue
            out({"jsonrpc": "2.0", "id": mid, "result": {
                "content": [{"type": "text", "text": text}],
                "isError": False}})
        elif mid is not None:
            out({"jsonrpc": "2.0", "id": mid, "error": {
                "code": -32601, "message": f"Method not found: {method}"}})


if __name__ == "__main__":
    main()

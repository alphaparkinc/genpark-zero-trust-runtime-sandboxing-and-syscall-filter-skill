"""MCP server for Zero-Trust Runtime Sandboxing & Syscall Filter."""
import sys
import json
from client import ZeroTrustSyscallFilter

def handle_request(req):
    method = req.get("method")
    if method == "tools/list":
        return {
            "tools": [{
                "name": "evaluate_sandbox_syscalls",
                "description": "Validates syscall traces and egress IPs against zero-trust policies",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "syscall_log": {"type": "array"},
                        "egress_ips": {"type": "array"}
                    },
                    "required": ["syscall_log", "egress_ips"]
                }
            }]
        }
    elif method == "tools/call":
        params = req.get("params", {})
        if params.get("name") == "evaluate_sandbox_syscalls":
            args = params.get("arguments", {})
            res = ZeroTrustSyscallFilter.evaluate_sandbox_calls(
                args.get("syscall_log", []),
                args.get("egress_ips", [])
            )
            return {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]}
    return {"error": "Method not found"}

if __name__ == "__main__":
    for line in sys.stdin:
        if line.strip():
            print(json.dumps(handle_request(json.loads(line))))
            sys.stdout.flush()

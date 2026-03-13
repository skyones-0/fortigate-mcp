#!/bin/bash
# Wrapper de diagnóstico para MCP FortiGate

exec >> /tmp/mcp-fortigate-debug.log 2>&1

echo "=============================================="
echo "MCP Debug - $(date)"
echo "PID: $$"
echo "PPID: $PPID"
echo "Args: $@"
echo "FORTIGATE_HOST: $FORTIGATE_HOST"
echo "FORTIGATE_API_TOKEN exists: $([ -n "$FORTIGATE_API_TOKEN" ] && echo YES || echo NO)"
echo "=============================================="

cd /Users/skyones/Developer/MCP/Fortigate
exec node mcp-server.mjs

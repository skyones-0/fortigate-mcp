#!/bin/bash
# Script de depuración para MCP FortiGate

echo "=== MCP FortiGate Debug ===" >&2
echo "FORTIGATE_HOST: $FORTIGATE_HOST" >&2
echo "FORTIGATE_API_TOKEN: ${FORTIGATE_API_TOKEN:0:10}..." >&2
echo "FORTIGATE_TOKEN: ${FORTIGATE_TOKEN:0:10}..." >&2
echo "PWD: $(pwd)" >&2
echo "Node version: $(node --version)" >&2

exec node /Users/skyones/Developer/MCP/Fortigate/dist/index.js

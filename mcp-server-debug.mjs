#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import https from 'https';
import { appendFileSync } from 'fs';

const LOG_FILE = '/tmp/mcp-fortigate-node.log';

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try {
    appendFileSync(LOG_FILE, line);
  } catch (e) {}
  console.error(line.trim());
}

log('=== MCP Server Starting ===');
log(`PID: ${process.pid}`);
log(`Args: ${JSON.stringify(process.argv)}`);
log(`ENV FORTIGATE_HOST: ${process.env.FORTIGATE_HOST}`);
log(`ENV TOKEN exists: ${!!process.env.FORTIGATE_API_TOKEN}`);

const config = {
  host: process.env.FORTIGATE_HOST || '172.28.20.1',
  token: process.env.FORTIGATE_API_TOKEN || process.env.FORTIGATE_TOKEN || '',
  port: parseInt(process.env.FORTIGATE_PORT || '443'),
};

if (!config.token) {
  log('ERROR: No token');
  process.exit(1);
}

const baseURL = `https://${config.host}:${config.port}`;
const client = axios.create({
  baseURL,
  timeout: 30000,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  headers: { 'Authorization': `Bearer ${config.token}` },
});

const tools = [
  { name: 'get_system_status', description: 'Info del sistema', inputSchema: { type: 'object', properties: {} } },
  { name: 'list_interfaces', description: 'Lista interfaces', inputSchema: { type: 'object', properties: {} } },
  { name: 'list_firewall_policies', description: 'Lista políticas', inputSchema: { type: 'object', properties: {} } },
  { 
    name: 'create_interface', 
    description: 'Crea o configura una interfaz (VLAN, Loopback, etc.)', 
    inputSchema: { 
      type: 'object', 
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz (e.g., port8, vlan100)' },
        alias: { type: 'string', description: 'Alias descriptivo (e.g., SAN, Management)' },
        ip: { type: 'string', description: 'IP con máscara (e.g., 192.168.1.1 255.255.255.0)' },
        type: { type: 'string', enum: ['physical', 'vlan', 'loopback', 'tunnel'], description: 'Tipo de interfaz' },
        mode: { type: 'string', enum: ['static', 'dhcp'], description: 'Modo de direccionamiento' },
        vlanid: { type: 'number', description: 'VLAN ID (para VLANs)' },
        interface: { type: 'string', description: 'Interfaz padre (para VLANs)' },
        allowaccess: { type: 'string', description: 'Accesos permitidos (ping, https, ssh, http)' },
        status: { type: 'string', enum: ['up', 'down'], description: 'Estado' },
        role: { type: 'string', enum: ['lan', 'wan', 'dmz', 'undefined'], description: 'Rol' },
      },
      required: ['name']
    } 
  },
  { 
    name: 'update_interface', 
    description: 'Actualiza una interfaz existente', 
    inputSchema: { 
      type: 'object', 
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz' },
        alias: { type: 'string', description: 'Alias descriptivo' },
        ip: { type: 'string', description: 'IP con máscara' },
        allowaccess: { type: 'string', description: 'Accesos permitidos' },
        description: { type: 'string', description: 'Descripción' },
        status: { type: 'string', enum: ['up', 'down'], description: 'Estado' },
        role: { type: 'string', enum: ['lan', 'wan', 'dmz', 'undefined'], description: 'Rol' },
      },
      required: ['name']
    } 
  },
];

const server = new Server(
  { name: 'mcp-fortigate', version: '1.1.0' },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  log('Handler: ListTools');
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  log(`Handler: CallTool ${name}`);
  
  try {
    let result;
    switch (name) {
      case 'get_system_status': {
        result = await client.get('/api/v2/monitor/system/status');
        return { content: [{ type: 'text', text: JSON.stringify(result.data, null, 2) }] };
      }
      case 'list_interfaces': {
        result = await client.get('/api/v2/cmdb/system/interface');
        return { content: [{ type: 'text', text: JSON.stringify(result.data.results || result.data, null, 2) }] };
      }
      case 'list_firewall_policies': {
        result = await client.get('/api/v2/cmdb/firewall/policy');
        return { content: [{ type: 'text', text: JSON.stringify(result.data.results || result.data, null, 2) }] };
      }
      case 'create_interface': {
        const { name: ifaceName, alias, ip, type, mode, vlanid, interface: parentIface, allowaccess, status, role } = args;
        
        // Build interface data
        const ifaceData = { name: ifaceName };
        if (alias) ifaceData.alias = alias;
        if (ip) ifaceData.ip = ip;
        if (type) ifaceData.type = type;
        if (mode) ifaceData.mode = mode;
        if (vlanid) ifaceData.vlanid = vlanid;
        if (parentIface) ifaceData.interface = parentIface;
        if (allowaccess) ifaceData.allowaccess = allowaccess;
        if (status) ifaceData.status = status;
        if (role) ifaceData.role = role;
        
        log(`Creating interface: ${ifaceName} with data: ${JSON.stringify(ifaceData)}`);
        
        try {
          // Try to create the interface
          result = await client.post('/api/v2/cmdb/system/interface', ifaceData);
          log(`Interface created successfully`);
          return { content: [{ type: 'text', text: JSON.stringify({ success: true, result: result.data }, null, 2) }] };
        } catch (createError) {
          // If creation fails (interface might already exist), try to update it
          if (createError.response?.status === 400 || createError.response?.data?.error?.includes('exists')) {
            log(`Interface may exist, trying update instead`);
            result = await client.put(`/api/v2/cmdb/system/interface/${ifaceName}`, ifaceData);
            log(`Interface updated successfully`);
            return { content: [{ type: 'text', text: JSON.stringify({ success: true, updated: true, result: result.data }, null, 2) }] };
          }
          throw createError;
        }
      }
      case 'update_interface': {
        const { name: ifaceName, alias, ip, allowaccess, description, status, role } = args;
        
        // Build update data
        const updateData = {};
        if (alias) updateData.alias = alias;
        if (ip) updateData.ip = ip;
        if (allowaccess) updateData.allowaccess = allowaccess;
        if (description) updateData.description = description;
        if (status) updateData.status = status;
        if (role) updateData.role = role;
        
        log(`Updating interface: ${ifaceName} with data: ${JSON.stringify(updateData)}`);
        result = await client.put(`/api/v2/cmdb/system/interface/${ifaceName}`, updateData);
        log(`Interface updated successfully`);
        return { content: [{ type: 'text', text: JSON.stringify({ success: true, result: result.data }, null, 2) }] };
      }
      default: 
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    log(`Error: ${error.message}`);
    const errorDetails = error.response?.data ? ` - Details: ${JSON.stringify(error.response.data)}` : '';
    return {
      content: [{ type: 'text', text: `Error: ${error.message}${errorDetails}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
log('MCP Server Ready');

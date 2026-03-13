#!/usr/bin/env node
/**
 * MCP FortiGate Server - Versión completa con operaciones CRUD
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import axios from 'axios';
import https from 'https';

// Configuración
const config = {
  host: process.env.FORTIGATE_HOST || '172.28.20.1',
  token: process.env.FORTIGATE_API_TOKEN || process.env.FORTIGATE_TOKEN || '',
  port: parseInt(process.env.FORTIGATE_PORT || '443'),
  https: process.env.FORTIGATE_HTTPS !== 'false',
  verifySsl: process.env.FORTIGATE_VERIFY_SSL === 'true',
};

if (!config.token) {
  console.error('ERROR: FORTIGATE_API_TOKEN no configurado');
  process.exit(1);
}

// Cliente HTTP
const baseURL = `${config.https ? 'https' : 'http'}://${config.host}:${config.port}`;
const client = axios.create({
  baseURL,
  timeout: 30000,
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
  headers: {
    'Authorization': `Bearer ${config.token}`,
    'Content-Type': 'application/json',
  },
});

// Helper para requests
async function apiGet(endpoint) {
  const result = await client.get(endpoint);
  return result.data.results || result.data;
}

async function apiPost(endpoint, data) {
  const result = await client.post(endpoint, data);
  return result.data;
}

async function apiPut(endpoint, data) {
  const result = await client.put(endpoint, data);
  return result.data;
}

async function apiDelete(endpoint) {
  const result = await client.delete(endpoint);
  return result.data;
}

// Tools definition - TODAS las herramientas disponibles
const tools = [
  // === System ===
  {
    name: 'get_system_status',
    description: 'Obtiene información del sistema FortiGate',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_system_config',
    description: 'Obtiene la configuración del sistema',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_system_time',
    description: 'Obtiene la hora del sistema',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_system_global',
    description: 'Obtiene la configuración global del sistema',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'update_system_global',
    description: 'Actualiza la configuración global del sistema',
    inputSchema: {
      type: 'object',
      properties: {
        hostname: { type: 'string', description: 'Hostname del FortiGate' },
        alias: { type: 'string', description: 'Alias del sistema' },
        admintimeout: { type: 'number', description: 'Timeout de administrador (minutos)' },
        'admin-https-redirect': { type: 'string', enum: ['enable', 'disable'] },
        'admin-sport': { type: 'number', description: 'Puerto HTTPS' },
        timezone: { type: 'string', description: 'Zona horaria' },
      },
    },
  },

  // === Interfaces ===
  {
    name: 'list_interfaces',
    description: 'Lista interfaces de red',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_interface',
    description: 'Obtiene detalles de una interfaz específica',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz' },
      },
      required: ['name'],
    },
  },
  {
    name: 'create_interface',
    description: 'Crea una nueva interfaz (VLAN, Loopback, Tunnel, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz (e.g., vlan100, loopback1)' },
        alias: { type: 'string', description: 'Alias descriptivo (e.g., SAN, Management)' },
        ip: { type: 'string', description: 'IP con máscara (e.g., 192.168.1.1 255.255.255.0)' },
        type: { type: 'string', enum: ['vlan', 'loopback', 'tunnel', 'aggregate', 'redundant'], description: 'Tipo de interfaz' },
        mode: { type: 'string', enum: ['static', 'dhcp'], description: 'Modo de direccionamiento' },
        vlanid: { type: 'number', description: 'VLAN ID (para interfaces VLAN)' },
        interface: { type: 'string', description: 'Interfaz padre (para VLANs)' },
        allowaccess: { type: 'string', description: 'Accesos permitidos (ping, https, ssh, http, snmp, etc.)' },
        description: { type: 'string', description: 'Descripción' },
        status: { type: 'string', enum: ['up', 'down'], description: 'Estado' },
        role: { type: 'string', enum: ['lan', 'wan', 'dmz', 'undefined'], description: 'Rol' },
      },
      required: ['name', 'type'],
    },
  },
  {
    name: 'update_interface',
    description: 'Actualiza una interfaz existente (incluyendo interfaces físicas)',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz (e.g., port8)' },
        alias: { type: 'string', description: 'Alias descriptivo (e.g., SAN)' },
        ip: { type: 'string', description: 'IP con máscara (e.g., 192.168.8.1 255.255.255.0)' },
        allowaccess: { type: 'string', description: 'Accesos permitidos (ping, https, ssh, http, snmp)' },
        description: { type: 'string', description: 'Descripción' },
        status: { type: 'string', enum: ['up', 'down'], description: 'Estado' },
        role: { type: 'string', enum: ['lan', 'wan', 'dmz', 'undefined'], description: 'Rol' },
        mode: { type: 'string', enum: ['static', 'dhcp', 'pppoe'], description: 'Modo de direccionamiento' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_interface',
    description: 'Elimina una interfaz (VLAN, Loopback, etc.)',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz a eliminar' },
      },
      required: ['name'],
    },
  },

  // === Firewall Policies ===
  {
    name: 'list_firewall_policies',
    description: 'Lista políticas de firewall',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_firewall_policy',
    description: 'Obtiene una política específica por ID',
    inputSchema: {
      type: 'object',
      properties: {
        policyid: { type: 'number', description: 'ID de la política' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'create_firewall_policy',
    description: 'Crea una nueva política de firewall',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de la política' },
        srcintf: { type: 'array', items: { type: 'string' }, description: 'Interfaces de origen' },
        dstintf: { type: 'array', items: { type: 'string' }, description: 'Interfaces de destino' },
        srcaddr: { type: 'array', items: { type: 'string' }, description: 'Direcciones de origen (all para any)' },
        dstaddr: { type: 'array', items: { type: 'string' }, description: 'Direcciones de destino (all para any)' },
        action: { type: 'string', enum: ['accept', 'deny'], description: 'Acción' },
        service: { type: 'array', items: { type: 'string' }, description: 'Servicios (ALL para todos)' },
        schedule: { type: 'string', description: 'Horario (always por defecto)' },
        nat: { type: 'string', enum: ['enable', 'disable'], description: 'Habilitar NAT' },
        logtraffic: { type: 'string', enum: ['all', 'utm', 'disable'], description: 'Logging' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado de la política' },
        comments: { type: 'string', description: 'Comentarios' },
      },
      required: ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'action', 'service'],
    },
  },
  {
    name: 'update_firewall_policy',
    description: 'Actualiza una política existente',
    inputSchema: {
      type: 'object',
      properties: {
        policyid: { type: 'number', description: 'ID de la política a actualizar' },
        name: { type: 'string', description: 'Nombre de la política' },
        srcintf: { type: 'array', items: { type: 'string' } },
        dstintf: { type: 'array', items: { type: 'string' } },
        srcaddr: { type: 'array', items: { type: 'string' } },
        dstaddr: { type: 'array', items: { type: 'string' } },
        action: { type: 'string', enum: ['accept', 'deny'] },
        service: { type: 'array', items: { type: 'string' } },
        nat: { type: 'string', enum: ['enable', 'disable'] },
        logtraffic: { type: 'string', enum: ['all', 'utm', 'disable'] },
        status: { type: 'string', enum: ['enable', 'disable'] },
        comments: { type: 'string' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'delete_firewall_policy',
    description: 'Elimina una política de firewall',
    inputSchema: {
      type: 'object',
      properties: {
        policyid: { type: 'number', description: 'ID de la política a eliminar' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'move_firewall_policy',
    description: 'Mueve una política a una nueva posición',
    inputSchema: {
      type: 'object',
      properties: {
        policyid: { type: 'number', description: 'ID de la política a mover' },
        before: { type: 'number', description: 'Mover antes de esta política' },
        after: { type: 'number', description: 'Mover después de esta política' },
      },
      required: ['policyid'],
    },
  },

  // === Address Objects ===
  {
    name: 'list_address_objects',
    description: 'Lista objetos de dirección',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_address_object',
    description: 'Crea un objeto de dirección',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        type: { type: 'string', enum: ['ipmask', 'iprange', 'fqdn', 'geography', 'wildcard'], description: 'Tipo de objeto' },
        subnet: { type: 'string', description: 'Subred (e.g., 192.168.1.0 255.255.255.0)' },
        start_ip: { type: 'string', description: 'IP inicial para rango' },
        end_ip: { type: 'string', description: 'IP final para rango' },
        fqdn: { type: 'string', description: 'Nombre FQDN' },
        country: { type: 'string', description: 'Código de país' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['name', 'type'],
    },
  },
  {
    name: 'update_address_object',
    description: 'Actualiza un objeto de dirección',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        subnet: { type: 'string' },
        start_ip: { type: 'string' },
        end_ip: { type: 'string' },
        fqdn: { type: 'string' },
        comment: { type: 'string' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_address_object',
    description: 'Elimina un objeto de dirección',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del objeto a eliminar' },
      },
      required: ['name'],
    },
  },

  // === Address Groups ===
  {
    name: 'list_address_groups',
    description: 'Lista grupos de dirección',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_address_group',
    description: 'Crea un grupo de direcciones',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        member: { type: 'array', items: { type: 'string' }, description: 'Miembros del grupo' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['name', 'member'],
    },
  },
  {
    name: 'delete_address_group',
    description: 'Elimina un grupo de direcciones',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
      },
      required: ['name'],
    },
  },

  // === Services ===
  {
    name: 'list_service_objects',
    description: 'Lista objetos de servicio personalizados',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_service_object',
    description: 'Crea un objeto de servicio personalizado',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del servicio' },
        protocol: { type: 'string', enum: ['TCP', 'UDP', 'SCTP', 'ICMP', 'IP'], description: 'Protocolo' },
        'tcp-portrange': { type: 'string', description: 'Rango de puertos TCP (e.g., 80-443, 8080)' },
        'udp-portrange': { type: 'string', description: 'Rango de puertos UDP' },
        'sctp-portrange': { type: 'string', description: 'Rango de puertos SCTP' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['name', 'protocol'],
    },
  },
  {
    name: 'delete_service_object',
    description: 'Elimina un objeto de servicio',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del servicio' },
      },
      required: ['name'],
    },
  },

  // === VIPs (Port Forwarding) ===
  {
    name: 'list_vips',
    description: 'Lista VIPs (Virtual IPs)',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_vip',
    description: 'Crea un VIP para port forwarding',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del VIP' },
        extip: { type: 'string', description: 'IP externa (0.0.0.0 para any)' },
        mappedip: { type: 'string', description: 'IP interna mapeada' },
        extintf: { type: 'string', description: 'Interfaz externa' },
        portforward: { type: 'string', enum: ['enable', 'disable'], description: 'Habilitar port forwarding' },
        protocol: { type: 'string', enum: ['tcp', 'udp', 'sctp'], description: 'Protocolo' },
        extport: { type: 'string', description: 'Puerto externo' },
        mappedport: { type: 'string', description: 'Puerto mapeado interno' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['name', 'extip', 'mappedip', 'extintf'],
    },
  },
  {
    name: 'delete_vip',
    description: 'Elimina un VIP',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del VIP' },
      },
      required: ['name'],
    },
  },

  // === Static Routes ===
  {
    name: 'list_static_routes',
    description: 'Lista rutas estáticas',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_static_route',
    description: 'Crea una ruta estática',
    inputSchema: {
      type: 'object',
      properties: {
        seq_num: { type: 'number', description: 'Número de secuencia (autogenerado si no se especifica)' },
        dst: { type: 'string', description: 'Destino (e.g., 192.168.100.0 255.255.255.0)' },
        gateway: { type: 'string', description: 'Gateway' },
        device: { type: 'string', description: 'Interfaz de salida' },
        distance: { type: 'number', description: 'Distancia administrativa (default: 10)' },
        priority: { type: 'number', description: 'Prioridad' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['dst', 'gateway', 'device'],
    },
  },
  {
    name: 'delete_static_route',
    description: 'Elimina una ruta estática',
    inputSchema: {
      type: 'object',
      properties: {
        seq_num: { type: 'number', description: 'Número de secuencia de la ruta' },
      },
      required: ['seq_num'],
    },
  },

  // === DHCP Server ===
  {
    name: 'list_dhcp_servers',
    description: 'Lista servidores DHCP',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_dhcp_server',
    description: 'Crea un servidor DHCP en una interfaz',
    inputSchema: {
      type: 'object',
      properties: {
        interface: { type: 'string', description: 'Interfaz donde habilitar DHCP' },
        'lease-time': { type: 'number', description: 'Tiempo de lease en segundos' },
        'dns-server1': { type: 'string', description: 'DNS primario' },
        'dns-server2': { type: 'string', description: 'DNS secundario' },
        domain: { type: 'string', description: 'Dominio' },
        'default-gateway': { type: 'string', description: 'Gateway por defecto' },
        netmask: { type: 'string', description: 'Máscara de red' },
      },
      required: ['interface'],
    },
  },

  // === Users ===
  {
    name: 'list_users',
    description: 'Lista usuarios locales',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_user',
    description: 'Crea un usuario local',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de usuario' },
        status: { type: 'string', enum: ['enable', 'disable'] },
        type: { type: 'string', enum: ['password', 'ldap', 'radius', 'tacacs-plus'], description: 'Tipo de autenticación' },
        passwd: { type: 'string', description: 'Contraseña' },
        email_to: { type: 'string', description: 'Correo electrónico' },
        comment: { type: 'string', description: 'Comentario' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_user',
    description: 'Elimina un usuario local',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre de usuario' },
      },
      required: ['name'],
    },
  },

  // === VPN IPsec ===
  {
    name: 'list_vpn_ipsec_phase1',
    description: 'Lista túneles VPN IPsec Phase 1',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'create_vpn_ipsec_phase1',
    description: 'Crea un túnel VPN IPsec Phase 1',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Nombre del túnel' },
        interface: { type: 'string', description: 'Interfaz de salida' },
        ike_version: { type: 'string', enum: ['1', '2'], description: 'Versión IKE' },
        peertype: { type: 'string', enum: ['any', 'one', 'dialup'], description: 'Tipo de peer' },
        proposal: { type: 'array', items: { type: 'string' }, description: 'Propuestas de cifrado' },
        psksecret: { type: 'string', description: 'Pre-shared key' },
        remote_gw: { type: 'string', description: 'IP del gateway remoto' },
        dpd: { type: 'string', enum: ['disable', 'on-idle', 'on-demand'], description: 'Dead Peer Detection' },
      },
      required: ['name', 'interface'],
    },
  },

  // === Security Profiles ===
  {
    name: 'list_antivirus_profiles',
    description: 'Lista perfiles de antivirus',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_webfilter_profiles',
    description: 'Lista perfiles de filtrado web',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_ips_sensors',
    description: 'Lista sensores IPS',
    inputSchema: { type: 'object', properties: {} },
  },

  // === Monitoring ===
  {
    name: 'get_system_performance',
    description: 'Obtiene estadísticas de rendimiento',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_dhcp_leases',
    description: 'Obtiene leases DHCP activos',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_arp_table',
    description: 'Obtiene tabla ARP',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'get_routing_table',
    description: 'Obtiene tabla de routing',
    inputSchema: { type: 'object', properties: {} },
  },

  // === Config Backup/Restore ===
  {
    name: 'backup_config',
    description: 'Realiza backup de la configuración',
    inputSchema: {
      type: 'object',
      properties: {
        scope: { type: 'string', enum: ['global', 'vdom'], description: 'Alcance del backup' },
      },
    },
  },
  {
    name: 'execute_cli_command',
    description: 'Ejecuta un comando CLI en el FortiGate',
    inputSchema: {
      type: 'object',
      properties: {
        command: { type: 'string', description: 'Comando CLI a ejecutar' },
      },
      required: ['command'],
    },
  },
];

// Create server
const server = new Server(
  { name: 'mcp-fortigate', version: '2.0.0' },
  { capabilities: { tools: {} } }
);

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Call tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;
  
  try {
    let result;
    
    switch (name) {
      // === System ===
      case 'get_system_status':
        result = await apiGet('/api/v2/monitor/system/status');
        break;
      case 'get_system_config':
        result = await apiGet('/api/v2/cmdb/system/config');
        break;
      case 'get_system_time':
        result = await apiGet('/api/v2/monitor/system/time');
        break;
      case 'get_system_global':
        result = await apiGet('/api/v2/cmdb/system/global');
        break;
      case 'update_system_global':
        result = await apiPut('/api/v2/cmdb/system/global', args);
        break;

      // === Interfaces ===
      case 'list_interfaces':
        result = await apiGet('/api/v2/cmdb/system/interface');
        break;
      case 'get_interface':
        result = await apiGet(`/api/v2/cmdb/system/interface/${args.name}`);
        break;
      case 'create_interface':
        result = await apiPost('/api/v2/cmdb/system/interface', args);
        break;
      case 'update_interface':
        result = await apiPut(`/api/v2/cmdb/system/interface/${args.name}`, args);
        break;
      case 'delete_interface':
        result = await apiDelete(`/api/v2/cmdb/system/interface/${args.name}`);
        break;

      // === Firewall Policies ===
      case 'list_firewall_policies':
        result = await apiGet('/api/v2/cmdb/firewall/policy');
        break;
      case 'get_firewall_policy':
        result = await apiGet(`/api/v2/cmdb/firewall/policy/${args.policyid}`);
        break;
      case 'create_firewall_policy': {
        // Transform arrays to FortiGate format if needed
        const policyData = { ...args };
        if (policyData.srcintf) policyData.srcintf = policyData.srcintf.map(name => ({ name }));
        if (policyData.dstintf) policyData.dstintf = policyData.dstintf.map(name => ({ name }));
        if (policyData.srcaddr) policyData.srcaddr = policyData.srcaddr.map(name => ({ name }));
        if (policyData.dstaddr) policyData.dstaddr = policyData.dstaddr.map(name => ({ name }));
        if (policyData.service) policyData.service = policyData.service.map(name => ({ name }));
        result = await apiPost('/api/v2/cmdb/firewall/policy', policyData);
        break;
      }
      case 'update_firewall_policy': {
        const { policyid, ...updateData } = args;
        if (updateData.srcintf) updateData.srcintf = updateData.srcintf.map(name => ({ name }));
        if (updateData.dstintf) updateData.dstintf = updateData.dstintf.map(name => ({ name }));
        if (updateData.srcaddr) updateData.srcaddr = updateData.srcaddr.map(name => ({ name }));
        if (updateData.dstaddr) updateData.dstaddr = updateData.dstaddr.map(name => ({ name }));
        if (updateData.service) updateData.service = updateData.service.map(name => ({ name }));
        result = await apiPut(`/api/v2/cmdb/firewall/policy/${policyid}`, updateData);
        break;
      }
      case 'delete_firewall_policy':
        result = await apiDelete(`/api/v2/cmdb/firewall/policy/${args.policyid}`);
        break;
      case 'move_firewall_policy': {
        const { policyid, before, after } = args;
        const action = before ? 'before' : 'after';
        const refId = before || after;
        result = await apiPut(`/api/v2/cmdb/firewall/policy/${policyid}`, { 'policy-block': action, 'policyid': refId });
        break;
      }

      // === Address Objects ===
      case 'list_address_objects':
        result = await apiGet('/api/v2/cmdb/firewall/address');
        break;
      case 'create_address_object':
        result = await apiPost('/api/v2/cmdb/firewall/address', args);
        break;
      case 'update_address_object':
        result = await apiPut(`/api/v2/cmdb/firewall/address/${args.name}`, args);
        break;
      case 'delete_address_object':
        result = await apiDelete(`/api/v2/cmdb/firewall/address/${args.name}`);
        break;

      // === Address Groups ===
      case 'list_address_groups':
        result = await apiGet('/api/v2/cmdb/firewall/addrgrp');
        break;
      case 'create_address_group': {
        const groupData = {
          ...args,
          member: args.member.map(name => ({ name }))
        };
        result = await apiPost('/api/v2/cmdb/firewall/addrgrp', groupData);
        break;
      }
      case 'delete_address_group':
        result = await apiDelete(`/api/v2/cmdb/firewall/addrgrp/${args.name}`);
        break;

      // === Services ===
      case 'list_service_objects':
        result = await apiGet('/api/v2/cmdb/firewall.service/custom');
        break;
      case 'create_service_object':
        result = await apiPost('/api/v2/cmdb/firewall.service/custom', args);
        break;
      case 'delete_service_object':
        result = await apiDelete(`/api/v2/cmdb/firewall.service/custom/${args.name}`);
        break;

      // === VIPs ===
      case 'list_vips':
        result = await apiGet('/api/v2/cmdb/firewall/vip');
        break;
      case 'create_vip':
        result = await apiPost('/api/v2/cmdb/firewall/vip', args);
        break;
      case 'delete_vip':
        result = await apiDelete(`/api/v2/cmdb/firewall/vip/${args.name}`);
        break;

      // === Static Routes ===
      case 'list_static_routes':
        result = await apiGet('/api/v2/cmdb/router/static');
        break;
      case 'create_static_route':
        result = await apiPost('/api/v2/cmdb/router/static', args);
        break;
      case 'delete_static_route':
        result = await apiDelete(`/api/v2/cmdb/router/static/${args.seq_num}`);
        break;

      // === DHCP Server ===
      case 'list_dhcp_servers':
        result = await apiGet('/api/v2/cmdb/system.dhcp/server');
        break;
      case 'create_dhcp_server':
        result = await apiPost('/api/v2/cmdb/system.dhcp/server', args);
        break;

      // === Users ===
      case 'list_users':
        result = await apiGet('/api/v2/cmdb/user/local');
        break;
      case 'create_user':
        result = await apiPost('/api/v2/cmdb/user/local', args);
        break;
      case 'delete_user':
        result = await apiDelete(`/api/v2/cmdb/user/local/${args.name}`);
        break;

      // === VPN IPsec ===
      case 'list_vpn_ipsec_phase1':
        result = await apiGet('/api/v2/cmdb/vpn.ipsec/phase1-interface');
        break;
      case 'create_vpn_ipsec_phase1':
        result = await apiPost('/api/v2/cmdb/vpn.ipsec/phase1-interface', args);
        break;

      // === Security Profiles ===
      case 'list_antivirus_profiles':
        result = await apiGet('/api/v2/cmdb/antivirus/profile');
        break;
      case 'list_webfilter_profiles':
        result = await apiGet('/api/v2/cmdb/webfilter/profile');
        break;
      case 'list_ips_sensors':
        result = await apiGet('/api/v2/cmdb/ips/sensor');
        break;

      // === Monitoring ===
      case 'get_system_performance':
        result = await apiGet('/api/v2/monitor/system/resource');
        break;
      case 'get_dhcp_leases':
        result = await apiGet('/api/v2/monitor/system/dhcp');
        break;
      case 'get_arp_table':
        result = await apiGet('/api/v2/monitor/network/arp');
        break;
      case 'get_routing_table':
        result = await apiGet('/api/v2/monitor/router/ipv4');
        break;

      // === Config ===
      case 'backup_config':
        result = await apiGet('/api/v2/monitor/system/config/backup?scope=' + (args.scope || 'global'));
        break;
      case 'execute_cli_command':
        result = await apiPost('/api/v2/monitor/system/config/execute-cli', { commands: [args.command] });
        break;

      default:
        throw new Error(`Tool not found: ${name}`);
    }
    
    return {
      content: [{
        type: 'text',
        text: JSON.stringify(result, null, 2),
      }],
    };
  } catch (error) {
    const statusCode = error.response?.status;
    const errorData = error.response?.data;
    const errorMessage = errorData?.error?.message || error.message;
    
    let userMessage = `Error ${statusCode}: ${errorMessage}`;
    if (statusCode === 403) {
      userMessage = 'Error 403: Acceso denegado. El token de API no tiene permisos suficientes para esta operación.';
    } else if (statusCode === 404) {
      userMessage = `Error 404: Recurso no encontrado. Verifique que el objeto exista.`;
    } else if (statusCode === 400) {
      userMessage = `Error 400: Solicitud inválida. ${errorMessage}`;
    }
    
    return {
      content: [{
        type: 'text',
        text: userMessage,
      }],
      isError: true,
    };
  }
});

// Start server
const transport = new StdioServerTransport();
await server.connect(transport);
console.error(`MCP FortiGate v2.0 ready: ${config.host}`);

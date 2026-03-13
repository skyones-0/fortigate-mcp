#!/usr/bin/env node
/**
 * MCP Server para FortiGate V7.6
 * Implementa el Model Context Protocol para interactuar con firewalls FortiGate
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { FortiGateClient, FortiGateError } from './client/fortigate-client.js';
import type { StaticRoute } from './types/fortigate.js';
import * as validation from './utils/validation.js';

// Configuración del cliente FortiGate
const config = {
  host: process.env.FORTIGATE_HOST || '',
  apiToken: process.env.FORTIGATE_API_TOKEN || '',
  port: parseInt(process.env.FORTIGATE_PORT || '443'),
  https: process.env.FORTIGATE_HTTPS !== 'false',
  verifySsl: process.env.FORTIGATE_VERIFY_SSL === 'true',
  timeout: parseInt(process.env.FORTIGATE_TIMEOUT || '30000'),
};

// Verificar configuración
if (!config.host || !config.apiToken) {
  console.error('Error: FORTIGATE_HOST y FORTIGATE_API_TOKEN son requeridos');
  console.error('Por favor configure las variables de entorno:');
  console.error('  - FORTIGATE_HOST: IP o hostname del FortiGate');
  console.error('  - FORTIGATE_API_TOKEN: Token de API de FortiGate');
  console.error('  - FORTIGATE_PORT: Puerto (default: 443)');
  console.error('  - FORTIGATE_HTTPS: Usar HTTPS (default: true)');
  console.error('  - FORTIGATE_VERIFY_SSL: Verificar SSL (default: false)');
  console.error('  - FORTIGATE_TIMEOUT: Timeout en ms (default: 30000)');
  process.exit(1);
}

// Crear cliente FortiGate
const client = new FortiGateClient(config);

// Crear servidor MCP
const server = new Server(
  {
    name: 'mcp-fortigate',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Definición de herramientas
const TOOLS = [
  // === Firewall Policies ===
  {
    name: 'list_firewall_policies',
    description: 'Lista todas las políticas de firewall',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'get_firewall_policy',
    description: 'Obtiene una política de firewall por ID',
    inputSchema: {
      type: 'object' as const,
      properties: {
        policyid: { type: 'number', description: 'ID de la política' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'create_firewall_policy',
    description: 'Crea una nueva política de firewall',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la política' },
        srcintf: { type: ['string', 'array'], description: 'Interfaces de origen' },
        dstintf: { type: ['string', 'array'], description: 'Interfaces de destino' },
        srcaddr: { type: ['string', 'array'], description: 'Direcciones de origen' },
        dstaddr: { type: ['string', 'array'], description: 'Direcciones de destino' },
        action: { type: 'string', enum: ['accept', 'deny', 'ipsec', 'ssl-vpn'], description: 'Acción' },
        schedule: { type: 'string', description: 'Horario' },
        service: { type: ['string', 'array'], description: 'Servicios' },
        logtraffic: { type: 'string', enum: ['all', 'utm', 'disable'], description: 'Logging' },
        nat: { type: 'string', enum: ['enable', 'disable'], description: 'NAT' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        comments: { type: 'string', description: 'Comentarios' },
        groups: { type: 'array', items: { type: 'string' }, description: 'Grupos de usuarios' },
        users: { type: 'array', items: { type: 'string' }, description: 'Usuarios' },
        ips_sensor: { type: 'string', description: 'Sensor IPS' },
        webfilter_profile: { type: 'string', description: 'Perfil Web Filter' },
        dnsfilter_profile: { type: 'string', description: 'Perfil DNS Filter' },
        av_profile: { type: 'string', description: 'Perfil Antivirus' },
        app_profile: { type: 'string', description: 'Perfil Application Control' },
        ssl_ssh_profile: { type: 'string', description: 'Perfil SSL/SSH' },
        waf_profile: { type: 'string', description: 'Perfil WAF' },
        profile_protocol_options: { type: 'string', description: 'Opciones de protocolo' },
        profile_group: { type: 'string', description: 'Grupo de perfiles' },
        poolname: { type: 'array', items: { type: 'string' }, description: 'IP Pools' },
        capture_packet: { type: 'string', enum: ['enable', 'disable'], description: 'Captura de paquetes' },
        ippool: { type: 'string', enum: ['enable', 'disable'], description: 'IP Pool' },
        fixedport: { type: 'string', enum: ['enable', 'disable'], description: 'Puerto fijo' },
        traffic_shaper: { type: 'string', description: 'Traffic Shaper' },
        traffic_shaper_reverse: { type: 'string', description: 'Traffic Shaper reverso' },
        per_ip_shaper: { type: 'string', description: 'Per-IP Shaper' },
        utm_status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado UTM' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'action', 'service'],
    },
  },
  {
    name: 'update_firewall_policy',
    description: 'Actualiza una política de firewall existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        policyid: { type: 'number', description: 'ID de la política' },
        name: { type: 'string', description: 'Nombre de la política' },
        srcintf: { type: ['string', 'array'], description: 'Interfaces de origen' },
        dstintf: { type: ['string', 'array'], description: 'Interfaces de destino' },
        srcaddr: { type: ['string', 'array'], description: 'Direcciones de origen' },
        dstaddr: { type: ['string', 'array'], description: 'Direcciones de destino' },
        action: { type: 'string', enum: ['accept', 'deny', 'ipsec', 'ssl-vpn'], description: 'Acción' },
        schedule: { type: 'string', description: 'Horario' },
        service: { type: ['string', 'array'], description: 'Servicios' },
        logtraffic: { type: 'string', enum: ['all', 'utm', 'disable'], description: 'Logging' },
        nat: { type: 'string', enum: ['enable', 'disable'], description: 'NAT' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        comments: { type: 'string', description: 'Comentarios' },
        groups: { type: 'array', items: { type: 'string' }, description: 'Grupos de usuarios' },
        users: { type: 'array', items: { type: 'string' }, description: 'Usuarios' },
        ips_sensor: { type: 'string', description: 'Sensor IPS' },
        webfilter_profile: { type: 'string', description: 'Perfil Web Filter' },
        dnsfilter_profile: { type: 'string', description: 'Perfil DNS Filter' },
        av_profile: { type: 'string', description: 'Perfil Antivirus' },
        app_profile: { type: 'string', description: 'Perfil Application Control' },
        ssl_ssh_profile: { type: 'string', description: 'Perfil SSL/SSH' },
        waf_profile: { type: 'string', description: 'Perfil WAF' },
        profile_protocol_options: { type: 'string', description: 'Opciones de protocolo' },
        profile_group: { type: 'string', description: 'Grupo de perfiles' },
        poolname: { type: 'array', items: { type: 'string' }, description: 'IP Pools' },
        capture_packet: { type: 'string', enum: ['enable', 'disable'], description: 'Captura de paquetes' },
        ippool: { type: 'string', enum: ['enable', 'disable'], description: 'IP Pool' },
        fixedport: { type: 'string', enum: ['enable', 'disable'], description: 'Puerto fijo' },
        traffic_shaper: { type: 'string', description: 'Traffic Shaper' },
        traffic_shaper_reverse: { type: 'string', description: 'Traffic Shaper reverso' },
        per_ip_shaper: { type: 'string', description: 'Per-IP Shaper' },
        utm_status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado UTM' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'delete_firewall_policy',
    description: 'Elimina una política de firewall',
    inputSchema: {
      type: 'object' as const,
      properties: {
        policyid: { type: 'number', description: 'ID de la política' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['policyid'],
    },
  },
  {
    name: 'move_firewall_policy',
    description: 'Mueve una política de firewall a una nueva posición',
    inputSchema: {
      type: 'object' as const,
      properties: {
        policyid: { type: 'number', description: 'ID de la política a mover' },
        before: { type: 'number', description: 'Mover antes de esta política' },
        after: { type: 'number', description: 'Mover después de esta política' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['policyid'],
    },
  },

  // === Address Objects ===
  {
    name: 'list_address_objects',
    description: 'Lista todos los objetos de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'get_address_object',
    description: 'Obtiene un objeto de dirección por nombre',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'create_address_object',
    description: 'Crea un nuevo objeto de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        subnet: { type: 'string', description: 'Subred (ej: 192.168.1.0 255.255.255.0)' },
        type: { type: 'string', enum: ['ipmask', 'iprange', 'fqdn', 'geography', 'wildcard', 'wildcard-fqdn', 'mac', 'dynamic', 'interface-subnet'], description: 'Tipo de dirección' },
        start_ip: { type: 'string', description: 'IP inicial (para tipo iprange)' },
        end_ip: { type: 'string', description: 'IP final (para tipo iprange)' },
        fqdn: { type: 'string', description: 'FQDN (para tipo fqdn)' },
        country: { type: 'string', description: 'País (para tipo geography)' },
        wildcard: { type: 'string', description: 'Wildcard (para tipo wildcard)' },
        macaddr: { type: 'array', items: { type: 'string' }, description: 'Direcciones MAC' },
        interface: { type: 'string', description: 'Interfaz' },
        comment: { type: 'string', description: 'Comentario' },
        associated_interface: { type: 'string', description: 'Interfaz asociada' },
        color: { type: 'number', description: 'Color' },
        allow_routing: { type: 'string', enum: ['enable', 'disable'], description: 'Permitir routing' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_address_object',
    description: 'Actualiza un objeto de dirección existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        subnet: { type: 'string', description: 'Subred' },
        type: { type: 'string', enum: ['ipmask', 'iprange', 'fqdn', 'geography', 'wildcard', 'wildcard-fqdn', 'mac', 'dynamic', 'interface-subnet'], description: 'Tipo de dirección' },
        start_ip: { type: 'string', description: 'IP inicial' },
        end_ip: { type: 'string', description: 'IP final' },
        fqdn: { type: 'string', description: 'FQDN' },
        country: { type: 'string', description: 'País' },
        wildcard: { type: 'string', description: 'Wildcard' },
        macaddr: { type: 'array', items: { type: 'string' }, description: 'Direcciones MAC' },
        interface: { type: 'string', description: 'Interfaz' },
        comment: { type: 'string', description: 'Comentario' },
        associated_interface: { type: 'string', description: 'Interfaz asociada' },
        color: { type: 'number', description: 'Color' },
        allow_routing: { type: 'string', enum: ['enable', 'disable'], description: 'Permitir routing' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_address_object',
    description: 'Elimina un objeto de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del objeto' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Address Groups ===
  {
    name: 'list_address_groups',
    description: 'Lista todos los grupos de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_address_group',
    description: 'Crea un nuevo grupo de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        member: { type: ['string', 'array'], description: 'Miembros del grupo' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name', 'member'],
    },
  },
  {
    name: 'update_address_group',
    description: 'Actualiza un grupo de dirección existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        member: { type: ['string', 'array'], description: 'Miembros del grupo' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_address_group',
    description: 'Elimina un grupo de dirección',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Service Objects ===
  {
    name: 'list_service_objects',
    description: 'Lista todos los objetos de servicio',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_service_object',
    description: 'Crea un nuevo objeto de servicio',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del servicio' },
        category: { type: 'string', description: 'Categoría' },
        protocol: { type: 'string', enum: ['TCP', 'UDP', 'SCTP', 'ICMP', 'ICMP6', 'IP'], description: 'Protocolo' },
        'tcp-portrange': { type: 'string', description: 'Rango de puertos TCP (ej: 80-443)' },
        'udp-portrange': { type: 'string', description: 'Rango de puertos UDP' },
        'sctp-portrange': { type: 'string', description: 'Rango de puertos SCTP' },
        icmptype: { type: 'number', description: 'Tipo ICMP' },
        icmpcode: { type: 'number', description: 'Código ICMP' },
        protocol_number: { type: 'number', description: 'Número de protocolo IP' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_service_object',
    description: 'Actualiza un objeto de servicio existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del servicio' },
        category: { type: 'string', description: 'Categoría' },
        protocol: { type: 'string', enum: ['TCP', 'UDP', 'SCTP', 'ICMP', 'ICMP6', 'IP'], description: 'Protocolo' },
        'tcp-portrange': { type: 'string', description: 'Rango de puertos TCP' },
        'udp-portrange': { type: 'string', description: 'Rango de puertos UDP' },
        'sctp-portrange': { type: 'string', description: 'Rango de puertos SCTP' },
        icmptype: { type: 'number', description: 'Tipo ICMP' },
        icmpcode: { type: 'number', description: 'Código ICMP' },
        protocol_number: { type: 'number', description: 'Número de protocolo IP' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_service_object',
    description: 'Elimina un objeto de servicio',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del servicio' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === VIPs ===
  {
    name: 'list_vips',
    description: 'Lista todos los VIPs (Virtual IPs)',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_vip',
    description: 'Crea un nuevo VIP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del VIP' },
        extip: { type: 'string', description: 'IP externa' },
        mappedip: { type: 'string', description: 'IP mapeada' },
        extintf: { type: 'string', description: 'Interfaz externa' },
        portforward: { type: 'string', enum: ['enable', 'disable'], description: 'Port forwarding' },
        protocol: { type: 'string', enum: ['tcp', 'udp', 'sctp'], description: 'Protocolo' },
        extport: { type: 'string', description: 'Puerto externo' },
        mappedport: { type: 'string', description: 'Puerto mapeado' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name', 'extip', 'mappedip', 'extintf'],
    },
  },
  {
    name: 'update_vip',
    description: 'Actualiza un VIP existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del VIP' },
        extip: { type: 'string', description: 'IP externa' },
        mappedip: { type: 'string', description: 'IP mapeada' },
        extintf: { type: 'string', description: 'Interfaz externa' },
        portforward: { type: 'string', enum: ['enable', 'disable'], description: 'Port forwarding' },
        protocol: { type: 'string', enum: ['tcp', 'udp', 'sctp'], description: 'Protocolo' },
        extport: { type: 'string', description: 'Puerto externo' },
        mappedport: { type: 'string', description: 'Puerto mapeado' },
        comment: { type: 'string', description: 'Comentario' },
        color: { type: 'number', description: 'Color' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_vip',
    description: 'Elimina un VIP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del VIP' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Interfaces ===
  {
    name: 'list_interfaces',
    description: 'Lista todas las interfaces',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'get_interface',
    description: 'Obtiene una interfaz por nombre',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_interface',
    description: 'Actualiza una interfaz existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la interfaz' },
        alias: { type: 'string', description: 'Alias' },
        ip: { type: 'string', description: 'Dirección IP' },
        allowaccess: { type: 'string', description: 'Accesos permitidos (ping, https, ssh, etc.)' },
        description: { type: 'string', description: 'Descripción' },
        status: { type: 'string', enum: ['up', 'down'], description: 'Estado' },
        role: { type: 'string', enum: ['lan', 'wan', 'dmz', 'undefined'], description: 'Rol' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Static Routes ===
  {
    name: 'list_static_routes',
    description: 'Lista todas las rutas estáticas',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_static_route',
    description: 'Crea una nueva ruta estática',
    inputSchema: {
      type: 'object' as const,
      properties: {
        seq_num: { type: 'number', description: 'Número de secuencia' },
        dst: { type: 'string', description: 'Destino (ej: 192.168.1.0 255.255.255.0)' },
        gateway: { type: 'string', description: 'Gateway' },
        device: { type: 'string', description: 'Dispositivo/Interfaz' },
        distance: { type: 'number', description: 'Distancia administrativa' },
        priority: { type: 'number', description: 'Prioridad' },
        comment: { type: 'string', description: 'Comentario' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        blackhole: { type: 'string', enum: ['enable', 'disable'], description: 'Blackhole route' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['dst', 'gateway'],
    },
  },
  {
    name: 'update_static_route',
    description: 'Actualiza una ruta estática existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        seq_num: { type: 'number', description: 'Número de secuencia' },
        dst: { type: 'string', description: 'Destino' },
        gateway: { type: 'string', description: 'Gateway' },
        device: { type: 'string', description: 'Dispositivo/Interfaz' },
        distance: { type: 'number', description: 'Distancia administrativa' },
        priority: { type: 'number', description: 'Prioridad' },
        comment: { type: 'string', description: 'Comentario' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        blackhole: { type: 'string', enum: ['enable', 'disable'], description: 'Blackhole route' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['seq_num'],
    },
  },
  {
    name: 'delete_static_route',
    description: 'Elimina una ruta estática',
    inputSchema: {
      type: 'object' as const,
      properties: {
        seq_num: { type: 'number', description: 'Número de secuencia' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['seq_num'],
    },
  },

  // === System Info ===
  {
    name: 'get_system_info',
    description: 'Obtiene información del sistema FortiGate',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_system_status',
    description: 'Obtiene el estado del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_system_config',
    description: 'Obtiene la configuración del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_system_time',
    description: 'Obtiene la hora del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },

  // === VDOMs ===
  {
    name: 'list_vdoms',
    description: 'Lista todos los VDOMs',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'create_vdom',
    description: 'Crea un nuevo VDOM',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del VDOM' },
        short_name: { type: 'string', description: 'Nombre corto' },
        vcluster_id: { type: 'number', description: 'ID del cluster virtual' },
        temporary: { type: 'number', description: 'Temporal (segundos)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_vdom',
    description: 'Elimina un VDOM',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del VDOM' },
      },
      required: ['name'],
    },
  },

  // === Users ===
  {
    name: 'list_users',
    description: 'Lista todos los usuarios locales',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_user',
    description: 'Crea un nuevo usuario local',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del usuario' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        type: { type: 'string', enum: ['password', 'radius', 'tacacs-plus', 'ldap', 'fortitoken', 'email', 'sms', 'certificate', 'saml', 'sso'], description: 'Tipo' },
        passwd: { type: 'string', description: 'Contraseña' },
        'two-factor': { type: 'string', enum: ['disable', 'fortitoken', 'email', 'sms'], description: 'Autenticación de dos factores' },
        email_to: { type: 'string', description: 'Email del usuario' },
        sms_server: { type: 'string', enum: ['fortiguard', 'custom'], description: 'Servidor SMS' },
        sms_custom_server: { type: 'string', description: 'Servidor SMS personalizado' },
        passwd_time: { type: 'string', description: 'Tiempo de expiración de contraseña' },
        passwd_policy: { type: 'string', description: 'Política de contraseña' },
        comment: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_user',
    description: 'Actualiza un usuario existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del usuario' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        type: { type: 'string', enum: ['password', 'radius', 'tacacs-plus', 'ldap', 'fortitoken', 'email', 'sms', 'certificate', 'saml', 'sso'], description: 'Tipo' },
        passwd: { type: 'string', description: 'Contraseña' },
        'two-factor': { type: 'string', enum: ['disable', 'fortitoken', 'email', 'sms'], description: 'Autenticación de dos factores' },
        email_to: { type: 'string', description: 'Email del usuario' },
        sms_server: { type: 'string', enum: ['fortiguard', 'custom'], description: 'Servidor SMS' },
        sms_custom_server: { type: 'string', description: 'Servidor SMS personalizado' },
        passwd_time: { type: 'string', description: 'Tiempo de expiración de contraseña' },
        passwd_policy: { type: 'string', description: 'Política de contraseña' },
        comment: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_user',
    description: 'Elimina un usuario',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del usuario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === User Groups ===
  {
    name: 'list_user_groups',
    description: 'Lista todos los grupos de usuarios',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_user_group',
    description: 'Crea un nuevo grupo de usuarios',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        member: { type: 'array', items: { type: 'string' }, description: 'Miembros del grupo' },
        'match-type': { type: 'string', enum: ['or', 'and'], description: 'Tipo de coincidencia' },
        'user-group-type': { type: 'string', enum: ['firewall', 'fsso', 'rsso', 'guest'], description: 'Tipo de grupo' },
        comment: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_user_group',
    description: 'Elimina un grupo de usuarios',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del grupo' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === VPN IPsec ===
  {
    name: 'list_vpn_ipsec_phase1',
    description: 'Lista todas las configuraciones VPN IPsec Phase 1',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_vpn_ipsec_phase1',
    description: 'Crea una nueva configuración VPN IPsec Phase 1',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la configuración' },
        interface: { type: 'string', description: 'Interfaz' },
        ike_version: { type: 'string', enum: ['1', '2'], description: 'Versión IKE' },
        peertype: { type: 'string', enum: ['any', 'one', 'dialup', 'peer', 'peergrp'], description: 'Tipo de peer' },
        proposal: { type: 'array', items: { type: 'string' }, description: 'Propuestas de cifrado' },
        local_gw: { type: 'string', description: 'Gateway local' },
        remote_gw: { type: 'string', description: 'Gateway remoto' },
        psksecret: { type: 'string', description: 'Pre-shared key' },
        dpd: { type: 'string', enum: ['disable', 'on-idle', 'on-demand'], description: 'Dead Peer Detection' },
        dhgrp: { type: ['string', 'array'], description: 'Grupos Diffie-Hellman' },
        keylifeseconds: { type: 'number', description: 'Tiempo de vida de la clave (segundos)' },
        nattraversal: { type: 'string', enum: ['enable', 'disable', 'forced'], description: 'NAT traversal' },
        comment: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name', 'interface'],
    },
  },
  {
    name: 'delete_vpn_ipsec_phase1',
    description: 'Elimina una configuración VPN IPsec Phase 1',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la configuración' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'list_vpn_ipsec_phase2',
    description: 'Lista todas las configuraciones VPN IPsec Phase 2',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_vpn_ipsec_phase2',
    description: 'Crea una nueva configuración VPN IPsec Phase 2',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la configuración' },
        phase1name: { type: 'string', description: 'Nombre de Phase 1' },
        proposal: { type: 'array', items: { type: 'string' }, description: 'Propuestas de cifrado' },
        dhgrp: { type: ['string', 'array'], description: 'Grupos Diffie-Hellman' },
        keylifeseconds: { type: 'number', description: 'Tiempo de vida de la clave (segundos)' },
        keylifekbs: { type: 'number', description: 'Tiempo de vida de la clave (KB)' },
        src_subnet: { type: 'string', description: 'Subred de origen' },
        dst_subnet: { type: 'string', description: 'Subred de destino' },
        src_name: { type: 'string', description: 'Nombre de dirección de origen' },
        dst_name: { type: 'string', description: 'Nombre de dirección de destino' },
        auto_negotiate: { type: 'string', enum: ['enable', 'disable'], description: 'Negociación automática' },
        comments: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name', 'phase1name'],
    },
  },
  {
    name: 'delete_vpn_ipsec_phase2',
    description: 'Elimina una configuración VPN IPsec Phase 2',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la configuración' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Security Profiles ===
  {
    name: 'list_antivirus_profiles',
    description: 'Lista todos los perfiles de antivirus',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_antivirus_profile',
    description: 'Crea un nuevo perfil de antivirus',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        comment: { type: 'string', description: 'Comentario' },
        'http-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear HTTP' },
        'ftp-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear FTP' },
        'imap-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear IMAP' },
        'pop3-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear POP3' },
        'smtp-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear SMTP' },
        'mapi-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear MAPI' },
        'nntp-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear NNTP' },
        'cifs-scan': { type: 'string', enum: ['enable', 'disable'], description: 'Escanear CIFS' },
        analytics_max_upload: { type: 'number', description: 'Máximo de subida para análisis' },
        analytics_db: { type: 'string', enum: ['enable', 'disable'], description: 'Base de datos de análisis' },
        analytics_bl: { type: 'string', enum: ['enable', 'disable'], description: 'Lista negra de análisis' },
        analytics_wl: { type: 'string', enum: ['enable', 'disable'], description: 'Lista blanca de análisis' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_antivirus_profile',
    description: 'Elimina un perfil de antivirus',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'list_webfilter_profiles',
    description: 'Lista todos los perfiles de filtrado web',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_webfilter_profile',
    description: 'Crea un nuevo perfil de filtrado web',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        comment: { type: 'string', description: 'Comentario' },
        feature_set: { type: 'string', enum: ['flow', 'proxy'], description: 'Conjunto de características' },
        inspection_mode: { type: 'string', enum: ['proxy', 'flow-based'], description: 'Modo de inspección' },
        options: { type: 'string', description: 'Opciones' },
        override: { type: 'array', items: { type: 'string' }, description: 'Overrides' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_webfilter_profile',
    description: 'Elimina un perfil de filtrado web',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'list_ips_sensors',
    description: 'Lista todos los sensores IPS',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_ips_sensor',
    description: 'Crea un nuevo sensor IPS',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del sensor' },
        comment: { type: 'string', description: 'Comentario' },
        'ips-filter': { type: 'string', description: 'Filtro IPS' },
        'log-packet': { type: 'string', enum: ['enable', 'disable'], description: 'Log de paquetes' },
        'packet-log-history': { type: 'number', description: 'Historial de log de paquetes' },
        'packet-log-memory': { type: 'number', description: 'Memoria de log de paquetes' },
        'packet-log-post-attack': { type: 'number', description: 'Log post-ataque' },
        'scan-botnet-connections': { type: 'string', enum: ['disable', 'block', 'monitor'], description: 'Escanear conexiones botnet' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_ips_sensor',
    description: 'Elimina un sensor IPS',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del sensor' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'list_ssl_ssh_profiles',
    description: 'Lista todos los perfiles SSL/SSH',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_ssl_ssh_profile',
    description: 'Crea un nuevo perfil SSL/SSH',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        comment: { type: 'string', description: 'Comentario' },
        ssl: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección SSL' },
        https: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección HTTPS' },
        ftps: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección FTPS' },
        imaps: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección IMAPS' },
        pop3s: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección POP3S' },
        smtps: { type: 'string', enum: ['disable', 'certificate-inspection', 'deep-inspection'], description: 'Inspección SMTPS' },
        ssh: { type: 'string', enum: ['disable', 'deep-inspection'], description: 'Inspección SSH' },
        'ssl-anomalies-log': { type: 'string', enum: ['enable', 'disable'], description: 'Log de anomalías SSL' },
        'ssl-exemptions-log': { type: 'string', enum: ['enable', 'disable'], description: 'Log de exenciones SSL' },
        'ssl-exemption': { type: 'array', items: { type: 'string' }, description: 'Exenciones SSL' },
        'ssl-exemption-ip': { type: 'array', items: { type: 'string' }, description: 'Exenciones SSL por IP' },
        'use-ssl-server': { type: 'string', enum: ['enable', 'disable'], description: 'Usar servidor SSL' },
        'ssl-server': { type: 'array', items: { type: 'string' }, description: 'Servidores SSL' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_ssl_ssh_profile',
    description: 'Elimina un perfil SSL/SSH',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del perfil' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === HA Config ===
  {
    name: 'get_ha_config',
    description: 'Obtiene la configuración de HA (High Availability)',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'update_ha_config',
    description: 'Actualiza la configuración de HA',
    inputSchema: {
      type: 'object' as const,
      properties: {
        mode: { type: 'string', enum: ['standalone', 'a-p', 'a-a'], description: 'Modo HA' },
        group_id: { type: 'number', description: 'ID del grupo' },
        group_name: { type: 'string', description: 'Nombre del grupo' },
        hbdev: { type: 'string', description: 'Heartbeat device' },
        priority: { type: 'number', description: 'Prioridad' },
        override: { type: 'string', enum: ['enable', 'disable'], description: 'Override' },
        password: { type: 'string', description: 'Contraseña HA' },
        monitor: { type: 'string', description: 'Interfaces a monitorear' },
        'pingserver-monitor-interface': { type: 'string', description: 'Interfaz para ping server' },
        'pingserver-failover-threshold': { type: 'number', description: 'Umbral de failover' },
        'pingserver-slave-force-reset': { type: 'string', enum: ['enable', 'disable'], description: 'Forzar reset de slave' },
        'ha-mgmt-status': { type: 'string', enum: ['enable', 'disable'], description: 'Estado de gestión HA' },
        'ha-mgmt-interface': { type: 'string', description: 'Interfaz de gestión HA' },
        'ha-mgmt-interface-gateway': { type: 'string', description: 'Gateway de gestión HA' },
        'session-pickup': { type: 'string', enum: ['enable', 'disable'], description: 'Session pickup' },
        'session-pickup-connectionless': { type: 'string', enum: ['enable', 'disable'], description: 'Session pickup connectionless' },
        'session-pickup-expectation': { type: 'string', enum: ['enable', 'disable'], description: 'Session pickup expectation' },
        'session-pickup-nat': { type: 'string', enum: ['enable', 'disable'], description: 'Session pickup NAT' },
        'session-pickup-delay': { type: 'string', enum: ['enable', 'disable'], description: 'Session pickup delay' },
        'link-failed-signal': { type: 'string', enum: ['enable', 'disable'], description: 'Señal de link failed' },
        'uninterruptible-upgrade': { type: 'string', enum: ['enable', 'disable'], description: 'Upgrade ininterrumpible' },
        'standalone-config-sync': { type: 'string', enum: ['enable', 'disable'], description: 'Sincronización de config standalone' },
        'ha-uptime-threshold': { type: 'number', description: 'Umbral de uptime HA' },
      },
    },
  },

  // === System Global ===
  {
    name: 'get_system_global',
    description: 'Obtiene la configuración global del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'update_system_global',
    description: 'Actualiza la configuración global del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {
        hostname: { type: 'string', description: 'Hostname' },
        alias: { type: 'string', description: 'Alias' },
        'timezone-option': { type: 'string', description: 'Opción de zona horaria' },
        timezone: { type: 'string', description: 'Zona horaria' },
        'gui-ipv6': { type: 'string', enum: ['enable', 'disable'], description: 'IPv6 en GUI' },
        'gui-certificates': { type: 'string', enum: ['enable', 'disable'], description: 'Certificados en GUI' },
        'gui-custom-language': { type: 'string', enum: ['enable', 'disable'], description: 'Lenguaje personalizado en GUI' },
        'gui-display-hostname': { type: 'string', enum: ['enable', 'disable'], description: 'Mostrar hostname en GUI' },
        'gui-theme': { type: 'string', enum: ['blue', 'green', 'red', 'melongene', 'mariner'], description: 'Tema GUI' },
        admintimeout: { type: 'number', description: 'Timeout de administrador' },
        'admin-https-ssl-versions': { type: 'string', description: 'Versiones SSL HTTPS' },
        'admin-https-redirect': { type: 'string', enum: ['enable', 'disable'], description: 'Redirección HTTPS' },
        'admin-sport': { type: 'number', description: 'Puerto HTTPS' },
        'admin-port': { type: 'number', description: 'Puerto HTTP' },
        'admin-ssh-port': { type: 'number', description: 'Puerto SSH' },
        'admin-telnet-port': { type: 'number', description: 'Puerto Telnet' },
        'admin-maintainer': { type: 'string', enum: ['enable', 'disable'], description: 'Modo maintainer' },
        'admin-scp': { type: 'string', enum: ['enable', 'disable'], description: 'SCP' },
        'cfg-save': { type: 'string', enum: ['automatic', 'manual', 'revert'], description: 'Modo de guardado de config' },
        language: { type: 'string', enum: ['english', 'simch', 'japanese', 'korean', 'spanish', 'trach'], description: 'Lenguaje' },
        'gui-date-format': { type: 'string', enum: ['yyyy/mm/dd', 'dd/mm/yyyy', 'mm/dd/yyyy', 'yyyy-mm-dd', 'dd-mm-yyyy', 'mm-dd-yyyy'], description: 'Formato de fecha' },
      },
    },
  },

  // === System Admin ===
  {
    name: 'list_system_admins',
    description: 'Lista todos los administradores del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'create_system_admin',
    description: 'Crea un nuevo administrador del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del administrador' },
        password: { type: 'string', description: 'Contraseña' },
        'peer-auth': { type: 'string', enum: ['enable', 'disable'], description: 'Autenticación peer' },
        'peer-group': { type: 'string', description: 'Grupo peer' },
        trusthost1: { type: 'string', description: 'Host confiable 1' },
        trusthost2: { type: 'string', description: 'Host confiable 2' },
        trusthost3: { type: 'string', description: 'Host confiable 3' },
        accprofile: { type: 'string', description: 'Perfil de acceso' },
        'allow-remove-admin-session': { type: 'string', enum: ['enable', 'disable'], description: 'Permitir remover sesión admin' },
        comments: { type: 'string', description: 'Comentarios' },
        'vdom-admin': { type: 'string', enum: ['enable', 'disable'], description: 'Admin VDOM' },
        vdom: { type: 'array', items: { type: 'string' }, description: 'VDOMs asignados' },
        wildcard: { type: 'string', enum: ['enable', 'disable'], description: 'Wildcard' },
        'remote-auth': { type: 'string', enum: ['enable', 'disable'], description: 'Autenticación remota' },
        'remote-group': { type: 'string', description: 'Grupo remoto' },
        'password-expire': { type: 'string', enum: ['enable', 'disable'], description: 'Expiración de contraseña' },
        'force-password-change': { type: 'string', enum: ['enable', 'disable'], description: 'Forzar cambio de contraseña' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_system_admin',
    description: 'Actualiza un administrador del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del administrador' },
        password: { type: 'string', description: 'Contraseña' },
        'peer-auth': { type: 'string', enum: ['enable', 'disable'], description: 'Autenticación peer' },
        'peer-group': { type: 'string', description: 'Grupo peer' },
        trusthost1: { type: 'string', description: 'Host confiable 1' },
        trusthost2: { type: 'string', description: 'Host confiable 2' },
        trusthost3: { type: 'string', description: 'Host confiable 3' },
        accprofile: { type: 'string', description: 'Perfil de acceso' },
        'allow-remove-admin-session': { type: 'string', enum: ['enable', 'disable'], description: 'Permitir remover sesión admin' },
        comments: { type: 'string', description: 'Comentarios' },
        'vdom-admin': { type: 'string', enum: ['enable', 'disable'], description: 'Admin VDOM' },
        vdom: { type: 'array', items: { type: 'string' }, description: 'VDOMs asignados' },
        wildcard: { type: 'string', enum: ['enable', 'disable'], description: 'Wildcard' },
        'remote-auth': { type: 'string', enum: ['enable', 'disable'], description: 'Autenticación remota' },
        'remote-group': { type: 'string', description: 'Grupo remoto' },
        'password-expire': { type: 'string', enum: ['enable', 'disable'], description: 'Expiración de contraseña' },
        'force-password-change': { type: 'string', enum: ['enable', 'disable'], description: 'Forzar cambio de contraseña' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_system_admin',
    description: 'Elimina un administrador del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del administrador' },
      },
      required: ['name'],
    },
  },

  // === Traffic Shapers ===
  {
    name: 'list_traffic_shapers',
    description: 'Lista todos los traffic shapers',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_traffic_shaper',
    description: 'Crea un nuevo traffic shaper',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del shaper' },
        'guaranteed-bandwidth': { type: 'number', description: 'Ancho de banda garantizado' },
        'maximum-bandwidth': { type: 'number', description: 'Ancho de banda máximo' },
        'bandwidth-unit': { type: 'string', enum: ['kbps', 'mbps', 'gbps'], description: 'Unidad de ancho de banda' },
        priority: { type: 'string', enum: ['low', 'medium', 'high', 'critical', 'top'], description: 'Prioridad' },
        'dscp-marking': { type: 'string', description: 'Marcado DSCP' },
        'per-policy': { type: 'string', enum: ['enable', 'disable'], description: 'Por política' },
        comment: { type: 'string', description: 'Comentario' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_traffic_shaper',
    description: 'Elimina un traffic shaper',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre del shaper' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === DHCP Server ===
  {
    name: 'list_dhcp_servers',
    description: 'Lista todos los servidores DHCP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_dhcp_server',
    description: 'Crea un nuevo servidor DHCP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'number', description: 'ID del servidor' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        'lease-time': { type: 'number', description: 'Tiempo de lease' },
        'mac-acl-default-action': { type: 'string', enum: ['assign', 'block'], description: 'Acción por defecto MAC ACL' },
        'forticlient-on-net-status': { type: 'string', enum: ['enable', 'disable'], description: 'Estado FortiClient on-net' },
        'dns-server1': { type: 'string', description: 'DNS Server 1' },
        'dns-server2': { type: 'string', description: 'DNS Server 2' },
        'domain': { type: 'string', description: 'Dominio' },
        'default-gateway': { type: 'string', description: 'Gateway por defecto' },
        'netmask': { type: 'string', description: 'Máscara de red' },
        interface: { type: 'string', description: 'Interfaz' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['interface'],
    },
  },
  {
    name: 'update_dhcp_server',
    description: 'Actualiza un servidor DHCP existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'number', description: 'ID del servidor' },
        status: { type: 'string', enum: ['enable', 'disable'], description: 'Estado' },
        'lease-time': { type: 'number', description: 'Tiempo de lease' },
        'mac-acl-default-action': { type: 'string', enum: ['assign', 'block'], description: 'Acción por defecto MAC ACL' },
        'forticlient-on-net-status': { type: 'string', enum: ['enable', 'disable'], description: 'Estado FortiClient on-net' },
        'dns-server1': { type: 'string', description: 'DNS Server 1' },
        'dns-server2': { type: 'string', description: 'DNS Server 2' },
        'domain': { type: 'string', description: 'Dominio' },
        'default-gateway': { type: 'string', description: 'Gateway por defecto' },
        'netmask': { type: 'string', description: 'Máscara de red' },
        interface: { type: 'string', description: 'Interfaz' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['id'],
    },
  },
  {
    name: 'delete_dhcp_server',
    description: 'Elimina un servidor DHCP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: { type: 'number', description: 'ID del servidor' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['id'],
    },
  },

  // === Zones ===
  {
    name: 'list_zones',
    description: 'Lista todas las zonas',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'create_zone',
    description: 'Crea una nueva zona',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la zona' },
        interface: { type: 'array', items: { type: 'string' }, description: 'Interfaces de la zona' },
        description: { type: 'string', description: 'Descripción' },
        intrazone: { type: 'string', enum: ['allow', 'deny'], description: 'Tráfico intra-zona' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'update_zone',
    description: 'Actualiza una zona existente',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la zona' },
        interface: { type: 'array', items: { type: 'string' }, description: 'Interfaces de la zona' },
        description: { type: 'string', description: 'Descripción' },
        intrazone: { type: 'string', enum: ['allow', 'deny'], description: 'Tráfico intra-zona' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'delete_zone',
    description: 'Elimina una zona',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Nombre de la zona' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['name'],
    },
  },

  // === Monitor/Logs ===
  {
    name: 'get_system_performance',
    description: 'Obtiene estadísticas de rendimiento del sistema',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_vpn_status',
    description: 'Obtiene el estado de las VPNs',
    inputSchema: {
      type: 'object' as const,
      properties: {},
    },
  },
  {
    name: 'get_dhcp_leases',
    description: 'Obtiene los leases DHCP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
        interface: { type: 'string', description: 'Interfaz específica' },
      },
    },
  },
  {
    name: 'get_arp_table',
    description: 'Obtiene la tabla ARP',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'get_routing_table',
    description: 'Obtiene la tabla de routing',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
    },
  },
  {
    name: 'get_session_list',
    description: 'Obtiene la lista de sesiones activas',
    inputSchema: {
      type: 'object' as const,
      properties: {
        vdom: { type: 'string', description: 'VDOM (default: root)' },
        count: { type: 'number', description: 'Número de sesiones a retornar' },
        filter: { type: 'string', description: 'Filtro de sesiones' },
        ip_version: { type: 'string', enum: ['ipv4', 'ipv6'], description: 'Versión IP' },
      },
    },
  },

  // === Config Management ===
  {
    name: 'backup_config',
    description: 'Realiza un backup de la configuración',
    inputSchema: {
      type: 'object' as const,
      properties: {
        scope: { type: 'string', enum: ['global', 'vdom'], description: 'Alcance del backup' },
      },
    },
  },
  {
    name: 'restore_config',
    description: 'Restaura la configuración desde un backup',
    inputSchema: {
      type: 'object' as const,
      properties: {
        config_content: { type: 'string', description: 'Contenido de la configuración en base64' },
        scope: { type: 'string', enum: ['global', 'vdom'], description: 'Alcance de la restauración' },
      },
      required: ['config_content'],
    },
  },
  {
    name: 'execute_cli_command',
    description: 'Ejecuta un comando CLI en el FortiGate',
    inputSchema: {
      type: 'object' as const,
      properties: {
        command: { type: 'string', description: 'Comando CLI a ejecutar' },
        vdom: { type: 'string', description: 'VDOM (default: root)' },
      },
      required: ['command'],
    },
  },
];

// Handler para listar herramientas
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: TOOLS,
  };
});

// Handler para ejecutar herramientas
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const vdom = (args?.vdom as string) || 'root';

  try {
    switch (name) {
      // === Firewall Policies ===
      case 'list_firewall_policies': {
        const policies = await client.getFirewallPolicies(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(policies, null, 2),
            },
          ],
        };
      }

      case 'get_firewall_policy': {
        const policyid = args?.policyid as number;
        const policy = await client.getFirewallPolicy(policyid, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(policy, null, 2),
            },
          ],
        };
      }

      case 'create_firewall_policy': {
        const validatedData = validation.validateData(validation.CreateFirewallPolicySchema, args);
        const result = await client.createFirewallPolicy(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_firewall_policy': {
        const policyid = args?.policyid as number;
        const validatedData = validation.validateData(validation.UpdateFirewallPolicySchema, args);
        const result = await client.updateFirewallPolicy(policyid, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_firewall_policy': {
        const policyid = args?.policyid as number;
        const result = await client.deleteFirewallPolicy(policyid, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'move_firewall_policy': {
        const policyid = args?.policyid as number;
        const before = args?.before as number | undefined;
        const after = args?.after as number | undefined;
        const position: 'before' | 'after' = before ? 'before' : 'after';
        const targetId = before || after || 0;
        const result = await client.moveFirewallPolicy(policyid, position, targetId, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Address Objects ===
      case 'list_address_objects': {
        const addresses = await client.getAddressObjects(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(addresses, null, 2),
            },
          ],
        };
      }

      case 'get_address_object': {
        const name = args?.name as string;
        const address = await client.getAddressObject(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(address, null, 2),
            },
          ],
        };
      }

      case 'create_address_object': {
        const validatedData = validation.validateData(validation.CreateAddressObjectSchema, args);
        const result = await client.createAddressObject(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_address_object': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateAddressObjectSchema, args);
        const result = await client.updateAddressObject(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_address_object': {
        const name = args?.name as string;
        const result = await client.deleteAddressObject(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Address Groups ===
      case 'list_address_groups': {
        const groups = await client.getAddressGroups(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(groups, null, 2),
            },
          ],
        };
      }

      case 'create_address_group': {
        const validatedData = validation.validateData(validation.CreateAddressGroupSchema, args);
        const result = await client.createAddressGroup(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_address_group': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateAddressGroupSchema, args);
        const result = await client.updateAddressGroup(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_address_group': {
        const name = args?.name as string;
        const result = await client.deleteAddressGroup(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Service Objects ===
      case 'list_service_objects': {
        const services = await client.getServiceObjects(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(services, null, 2),
            },
          ],
        };
      }

      case 'create_service_object': {
        const validatedData = validation.validateData(validation.CreateServiceObjectSchema, args);
        const result = await client.createServiceObject(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_service_object': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateServiceObjectSchema, args);
        const result = await client.updateServiceObject(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_service_object': {
        const name = args?.name as string;
        const result = await client.deleteServiceObject(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === VIPs ===
      case 'list_vips': {
        const vips = await client.getVIPs(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(vips, null, 2),
            },
          ],
        };
      }

      case 'create_vip': {
        const validatedData = validation.validateData(validation.CreateVIPSchema, args);
        const result = await client.createVIP(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_vip': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateVIPSchema, args);
        const result = await client.updateVIP(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_vip': {
        const name = args?.name as string;
        const result = await client.deleteVIP(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Interfaces ===
      case 'list_interfaces': {
        const interfaces = await client.getSystemInterfaces();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(interfaces, null, 2),
            },
          ],
        };
      }

      case 'get_interface': {
        const name = args?.name as string;
        const interfaces = await client.getSystemInterfaces();
        const iface = interfaces.find(i => i.name === name);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(iface || { error: 'Interface not found' }, null, 2),
            },
          ],
        };
      }

      case 'update_interface': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateInterfaceSchema, args);
        // Note: Interface update requires direct API call
        const result = await client.put(`/api/v2/cmdb/system/interface/${name}`, validatedData, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Static Routes ===
      case 'list_static_routes': {
        const routes = await client.getStaticRoutes(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(routes, null, 2),
            },
          ],
        };
      }

      case 'create_static_route': {
        const validatedData = validation.validateData(validation.CreateStaticRouteSchema, args);
        // Remove seq_num if undefined as it's auto-generated by FortiGate
        const { seq_num, ...routeData } = validatedData;
        const result = await client.createStaticRoute(routeData as StaticRoute, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_static_route': {
        const seq_num = args?.seq_num as number;
        const validatedData = validation.validateData(validation.UpdateStaticRouteSchema, args);
        const result = await client.updateStaticRoute(seq_num, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_static_route': {
        const seq_num = args?.seq_num as number;
        const result = await client.deleteStaticRoute(seq_num, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === System Info ===
      case 'get_system_info': {
        const info = await client.getSystemStatus();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(info, null, 2),
            },
          ],
        };
      }

      case 'get_system_status': {
        const status = await client.getSystemStatus();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(status, null, 2),
            },
          ],
        };
      }

      case 'get_system_config': {
        const config = await client.getSystemConfig();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(config, null, 2),
            },
          ],
        };
      }

      case 'get_system_time': {
        const time = await client.getSystemTime();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(time, null, 2),
            },
          ],
        };
      }

      // === VDOMs ===
      case 'list_vdoms': {
        const vdoms = await client.getVDOMs();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(vdoms, null, 2),
            },
          ],
        };
      }

      case 'create_vdom': {
        const validatedData = validation.validateData(validation.CreateVDOMSchema, args);
        const result = await client.createVDOM(validatedData);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_vdom': {
        const name = args?.name as string;
        const result = await client.deleteVDOM(name);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Users ===
      case 'list_users': {
        const users = await client.getLocalUsers(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(users, null, 2),
            },
          ],
        };
      }

      case 'create_user': {
        const validatedData = validation.validateData(validation.CreateUserLocalSchema, args);
        const result = await client.createLocalUser(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_user': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateUserLocalSchema, args);
        const result = await client.updateLocalUser(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_user': {
        const name = args?.name as string;
        const result = await client.deleteLocalUser(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === User Groups ===
      case 'list_user_groups': {
        const groups = await client.getUserGroups(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(groups, null, 2),
            },
          ],
        };
      }

      case 'create_user_group': {
        const validatedData = validation.validateData(validation.CreateUserGroupSchema, args);
        // Transform member array to expected format
        const data = {
          ...validatedData,
          member: validatedData.member?.map((m: string) => ({ name: m })) || []
        };
        const result = await client.createUserGroup(data, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_user_group': {
        const name = args?.name as string;
        const result = await client.deleteUserGroup(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === VPN IPsec ===
      case 'list_vpn_ipsec_phase1': {
        const phase1 = await client.getIPsecPhase1(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(phase1, null, 2),
            },
          ],
        };
      }

      case 'create_vpn_ipsec_phase1': {
        const validatedData = validation.validateData(validation.CreateVPNIPsecPhase1Schema, args);
        const result = await client.createIPsecPhase1(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_vpn_ipsec_phase1': {
        const name = args?.name as string;
        const result = await client.deleteIPsecPhase1(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'list_vpn_ipsec_phase2': {
        const phase2 = await client.getIPsecPhase2(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(phase2, null, 2),
            },
          ],
        };
      }

      case 'create_vpn_ipsec_phase2': {
        const validatedData = validation.validateData(validation.CreateVPNIPsecPhase2Schema, args);
        const result = await client.createIPsecPhase2(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_vpn_ipsec_phase2': {
        const name = args?.name as string;
        const result = await client.deleteIPsecPhase2(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Security Profiles ===
      case 'list_antivirus_profiles': {
        const profiles = await client.getAntivirusProfiles(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(profiles, null, 2),
            },
          ],
        };
      }

      case 'create_antivirus_profile': {
        const validatedData = validation.validateData(validation.CreateAntivirusProfileSchema, args);
        const result = await client.createAntivirusProfile(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_antivirus_profile': {
        const name = args?.name as string;
        const result = await client.deleteAntivirusProfile(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'list_webfilter_profiles': {
        const profiles = await client.getWebFilterProfiles(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(profiles, null, 2),
            },
          ],
        };
      }

      case 'create_webfilter_profile': {
        const validatedData = validation.validateData(validation.CreateWebFilterProfileSchema, args);
        // Fix inspection_mode type and ensure name is present
        const data: Record<string, unknown> = { ...validatedData };
        if (data.inspection_mode === 'flow-based') {
          data.inspection_mode = 'flow';
        }
        const result = await client.createWebFilterProfile(data as { name: string; [key: string]: unknown }, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_webfilter_profile': {
        const name = args?.name as string;
        const result = await client.deleteWebFilterProfile(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'list_ips_sensors': {
        const sensors = await client.getIPSSensors(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(sensors, null, 2),
            },
          ],
        };
      }

      case 'create_ips_sensor': {
        const validatedData = validation.validateData(validation.CreateIPSSensorSchema, args);
        const result = await client.createIPSSensor(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_ips_sensor': {
        const name = args?.name as string;
        const result = await client.deleteIPSSensor(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'list_ssl_ssh_profiles': {
        const profiles = await client.getSSLSSHProfiles(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(profiles, null, 2),
            },
          ],
        };
      }

      case 'create_ssl_ssh_profile': {
        const validatedData = validation.validateData(validation.CreateSSLSSHProfileSchema, args);
        // Transform ssl field to expected format
        const data: Record<string, unknown> = { ...validatedData };
        if (data.ssl === 'disable') {
          delete data.ssl;
        }
        const result = await client.createSSLSSHProfile(data as { name: string; [key: string]: unknown }, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_ssl_ssh_profile': {
        const name = args?.name as string;
        const result = await client.deleteSSLSSHProfile(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === HA Config ===
      case 'get_ha_config': {
        const haConfig = await client.getHAConfig();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(haConfig, null, 2),
            },
          ],
        };
      }

      case 'update_ha_config': {
        const validatedData = validation.validateData(validation.UpdateHAConfigSchema, args);
        const result = await client.updateHAConfig(validatedData);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === System Global ===
      case 'get_system_global': {
        const global = await client.getSystemGlobal();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(global, null, 2),
            },
          ],
        };
      }

      case 'update_system_global': {
        const validatedData = validation.validateData(validation.UpdateSystemGlobalSchema, args);
        const result = await client.updateSystemGlobal(validatedData);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === System Admin ===
      case 'list_system_admins': {
        const admins = await client.getSystemAdministrators();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(admins, null, 2),
            },
          ],
        };
      }

      case 'create_system_admin': {
        const validatedData = validation.validateData(validation.CreateSystemAdminSchema, args);
        const result = await client.createSystemAdministrator(validatedData);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_system_admin': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateSystemAdminSchema, args);
        const result = await client.updateSystemAdministrator(name, validatedData);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_system_admin': {
        const name = args?.name as string;
        const result = await client.deleteSystemAdministrator(name);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Traffic Shapers ===
      case 'list_traffic_shapers': {
        // Use generic API call since method may not exist
        const result = await client.get('/api/v2/cmdb/firewall.shaper/traffic-shaper', vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'create_traffic_shaper': {
        const validatedData = validation.validateData(validation.CreateTrafficShaperSchema, args);
        const result = await client.post('/api/v2/cmdb/firewall.shaper/traffic-shaper', validatedData, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'delete_traffic_shaper': {
        const name = args?.name as string;
        const result = await client.delete(`/api/v2/cmdb/firewall.shaper/traffic-shaper/${name}`, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === DHCP Server ===
      case 'list_dhcp_servers': {
        const result = await client.get('/api/v2/cmdb/system.dhcp/server', vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'create_dhcp_server': {
        const validatedData = validation.validateData(validation.CreateDHCPServerSchema, args);
        const result = await client.post('/api/v2/cmdb/system.dhcp/server', validatedData, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'update_dhcp_server': {
        const id = args?.id as number;
        const validatedData = validation.validateData(validation.UpdateDHCPServerSchema, args);
        const result = await client.put(`/api/v2/cmdb/system.dhcp/server/${id}`, validatedData, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'delete_dhcp_server': {
        const id = args?.id as number;
        const result = await client.delete(`/api/v2/cmdb/system.dhcp/server/${id}`, vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Zones ===
      case 'list_zones': {
        const zones = await client.getZones(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(zones, null, 2),
            },
          ],
        };
      }

      case 'create_zone': {
        const validatedData = validation.validateData(validation.CreateZoneSchema, args);
        const result = await client.createZone(validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'update_zone': {
        const name = args?.name as string;
        const validatedData = validation.validateData(validation.UpdateZoneSchema, args);
        const result = await client.updateZone(name, validatedData, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'delete_zone': {
        const name = args?.name as string;
        const result = await client.deleteZone(name, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      // === Monitor/Logs ===
      case 'get_system_performance': {
        const performance = await client.getSystemPerformance();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(performance, null, 2),
            },
          ],
        };
      }

      case 'get_vpn_status': {
        const vpnStatus = await client.getIPsecTunnels(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(vpnStatus, null, 2),
            },
          ],
        };
      }

      case 'get_dhcp_leases': {
        const iface = args?.interface as string | undefined;
        const params: Record<string, unknown> = vdom ? { vdom } : {};
        if (iface) params.interface = iface;
        const result = await client.get('/api/v2/monitor/system/dhcp', params);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'get_arp_table': {
        const result = await client.get('/api/v2/monitor/network/arp', vdom ? { vdom } : {});
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      case 'get_routing_table': {
        const routingTable = await client.getRoutingTable(vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(routingTable, null, 2),
            },
          ],
        };
      }

      case 'get_session_list': {
        const count = args?.count as number | undefined;
        const filter = args?.filter as string | undefined;
        const ip_version = args?.ip_version as 'ipv4' | 'ipv6' | undefined;
        const params: Record<string, unknown> = { count: count || 100 };
        if (vdom) params.vdom = vdom;
        if (filter) params.filter = filter;
        if (ip_version) params.ip_version = ip_version;
        const result = await client.get('/api/v2/monitor/firewall/session', params);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result.results, null, 2),
            },
          ],
        };
      }

      // === Config Management ===
      case 'backup_config': {
        const scope = (args?.scope as 'global' | 'vdom') || 'global';
        const config = await client.backupConfig(scope);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ backup: config }, null, 2),
            },
          ],
        };
      }

      case 'restore_config': {
        const config_content = args?.config_content as string;
        const scope = (args?.scope as 'global' | 'vdom') || 'global';
        const result = await client.restoreConfig(config_content, scope);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case 'execute_cli_command': {
        const command = args?.command as string;
        const result = await client.executeCLICommand(command, vdom);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      default:
        throw new McpError(
          ErrorCode.MethodNotFound,
          `Herramienta no encontrada: ${name}`
        );
    }
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }

    if (error instanceof FortiGateError) {
      throw new McpError(
        ErrorCode.InternalError,
        `Error de FortiGate: ${error.message} (Status: ${error.statusCode || 'N/A'})`
      );
    }

    if (error instanceof validation.z.ZodError) {
      const issues = error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', ');
      throw new McpError(
        ErrorCode.InvalidParams,
        `Error de validación: ${issues}`
      );
    }

    throw new McpError(
      ErrorCode.InternalError,
      `Error interno: ${error instanceof Error ? error.message : String(error)}`
    );
  }
});

// Iniciar servidor
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('MCP FortiGate Server iniciado');
}

main().catch((error) => {
  console.error('Error fatal:', error);
  process.exit(1);
});

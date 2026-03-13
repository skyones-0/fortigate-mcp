# MCP FortiGate Server

Servidor MCP (Model Context Protocol) completo para administración de firewalls FortiGate v7.6+. Proporciona acceso completo de lectura y escritura a través de la API REST de FortiGate.

## Características

- **40+ herramientas** para gestión completa del FortiGate
- Soporte para operaciones **CRUD** (Crear, Leer, Actualizar, Eliminar)
- Gestión de **interfaces**, **firewall policies**, **objetos**, **VPN**, **usuarios**
- Monitoreo del sistema en tiempo real
- Manejo de errores y validación de parámetros
- Compatible con FortiGate v7.6+

## Requisitos

- Node.js 18+
- FortiGate con acceso a la API REST habilitada
- Token de API con permisos adecuados

## Instalación

```bash
npm install
```

## Configuración

Crear archivo `.env` en el directorio raíz:

```env
FORTIGATE_HOST=192.168.1.1
FORTIGATE_API_TOKEN=tu_token_aqui
FORTIGATE_PORT=443
FORTIGATE_HTTPS=true
FORTIGATE_VERIFY_SSL=false
FORTIGATE_TIMEOUT=30000
```

### Generar Token de API en FortiGate

1. Ir a **System > Administrators**
2. Crear un administrador tipo **REST API Admin**
3. Asignar perfil de acceso con permisos **Read/Write**
4. Guardar el token generado

## Uso

### Desarrollo

```bash
npm run dev
```

### Producción

```bash
npm run build
npm start
```

## Herramientas Disponibles

### Sistema

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `get_system_status` | Obtiene información general del sistema | Lectura |
| `get_system_config` | Obtiene la configuración completa | Lectura |
| `get_system_time` | Obtiene la hora del sistema | Lectura |
| `get_system_global` | Obtiene configuración global | Lectura |
| `update_system_global` | Actualiza configuración global | Escritura |
| `backup_config` | Realiza backup de la configuración | Escritura |
| `execute_cli_command` | Ejecuta comandos CLI | Escritura |

### Interfaces

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_interfaces` | Lista todas las interfaces | Lectura |
| `get_interface` | Obtiene detalles de una interfaz | Lectura |
| `create_interface` | Crea VLANs, Loopbacks, Tunnels | Escritura |
| `update_interface` | Configura interfaces existentes | Escritura |
| `delete_interface` | Elimina interfaces virtuales | Escritura |

### Firewall Policies

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_firewall_policies` | Lista todas las políticas | Lectura |
| `get_firewall_policy` | Obtiene una política específica | Lectura |
| `create_firewall_policy` | Crea nueva política | Escritura |
| `update_firewall_policy` | Modifica política existente | Escritura |
| `delete_firewall_policy` | Elimina una política | Escritura |
| `move_firewall_policy` | Reordena políticas | Escritura |

### Objetos de Dirección

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_address_objects` | Lista objetos de dirección | Lectura |
| `create_address_object` | Crea objeto IP/Range/FQDN | Escritura |
| `update_address_object` | Actualiza objeto | Escritura |
| `delete_address_object` | Elimina objeto | Escritura |
| `list_address_groups` | Lista grupos de dirección | Lectura |
| `create_address_group` | Crea grupo de direcciones | Escritura |
| `delete_address_group` | Elimina grupo | Escritura |

### Servicios

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_service_objects` | Lista servicios personalizados | Lectura |
| `create_service_object` | Crea servicio TCP/UDP/etc | Escritura |
| `delete_service_object` | Elimina servicio | Escritura |

### VIPs (Port Forwarding)

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_vips` | Lista VIPs configurados | Lectura |
| `create_vip` | Crea regla de port forwarding | Escritura |
| `delete_vip` | Elimina VIP | Escritura |

### Routing

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_static_routes` | Lista rutas estáticas | Lectura |
| `create_static_route` | Crea ruta estática | Escritura |
| `delete_static_route` | Elimina ruta estática | Escritura |
| `get_routing_table` | Obtiene tabla de routing | Lectura |

### DHCP

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_dhcp_servers` | Lista servidores DHCP | Lectura |
| `create_dhcp_server` | Configura servidor DHCP | Escritura |
| `get_dhcp_leases` | Obtiene leases activos | Lectura |

### Usuarios

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_users` | Lista usuarios locales | Lectura |
| `create_user` | Crea usuario local | Escritura |
| `delete_user` | Elimina usuario | Escritura |

### VPN IPsec

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_vpn_ipsec_phase1` | Lista túneles VPN Phase 1 | Lectura |
| `create_vpn_ipsec_phase1` | Crea túnel VPN | Escritura |

### Perfiles de Seguridad

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `list_antivirus_profiles` | Lista perfiles antivirus | Lectura |
| `list_webfilter_profiles` | Lista perfiles web filter | Lectura |
| `list_ips_sensors` | Lista sensores IPS | Lectura |

### Monitoreo

| Herramienta | Descripción | Tipo |
|-------------|-------------|------|
| `get_system_performance` | Estadísticas de rendimiento | Lectura |
| `get_arp_table` | Tabla ARP | Lectura |
| `get_dhcp_leases` | Leases DHCP activos | Lectura |

## Ejemplos de Uso

### Crear una interfaz VLAN

```json
{
  "name": "create_interface",
  "arguments": {
    "name": "vlan100",
    "type": "vlan",
    "alias": "SAN_Network",
    "vlanid": 100,
    "interface": "port1",
    "ip": "192.168.100.1 255.255.255.0",
    "allowaccess": "ping https ssh",
    "role": "lan"
  }
}
```

### Actualizar interfaz física (port8 con alias SAN)

```json
{
  "name": "update_interface",
  "arguments": {
    "name": "port8",
    "alias": "SAN",
    "ip": "192.168.8.1 255.255.255.0",
    "allowaccess": "ping https ssh",
    "role": "lan",
    "status": "up"
  }
}
```

### Crear política de firewall

```json
{
  "name": "create_firewall_policy",
  "arguments": {
    "name": "LAN_to_WAN",
    "srcintf": ["port2"],
    "dstintf": ["port1"],
    "srcaddr": ["all"],
    "dstaddr": ["all"],
    "action": "accept",
    "service": ["ALL"],
    "nat": "enable",
    "logtraffic": "all",
    "schedule": "always"
  }
}
```

### Crear objeto de dirección

```json
{
  "name": "create_address_object",
  "arguments": {
    "name": "Server_DC01",
    "type": "ipmask",
    "subnet": "192.168.10.50 255.255.255.255",
    "comment": "Servidor principal de datos"
  }
}
```

### Crear ruta estática

```json
{
  "name": "create_static_route",
  "arguments": {
    "dst": "10.0.0.0 255.0.0.0",
    "gateway": "192.168.1.254",
    "device": "port1",
    "distance": 10,
    "comment": "Ruta a red corporativa"
  }
}
```

### Crear VIP (Port Forwarding)

```json
{
  "name": "create_vip",
  "arguments": {
    "name": "Web_Server_VIP",
    "extip": "203.0.113.10",
    "mappedip": "192.168.1.100",
    "extintf": "port1",
    "portforward": "enable",
    "protocol": "tcp",
    "extport": "80",
    "mappedport": "8080"
  }
}
```

## Estructura del Proyecto

```
├── src/
│   ├── index.ts              # Código fuente principal
│   ├── client/
│   │   └── fortigate-client.ts   # Cliente API
│   ├── types/
│   │   └── fortigate.ts      # Definiciones TypeScript
│   └── utils/
│       └── validation.ts     # Esquemas de validación
├── dist/                     # Código compilado
├── mcp-server.mjs            # Servidor MCP ejecutable
├── mcp-server-debug.mjs      # Versión debug
├── package.json
├── tsconfig.json
└── .env                      # Variables de entorno
```

## Scripts Disponibles

- `npm run build` - Compila TypeScript
- `npm run dev` - Ejecuta en modo desarrollo
- `npm start` - Ejecuta versión compilada
- `npm run lint` - Ejecuta linter

## Solución de Problemas

### Error 403 Forbidden

El token de API no tiene permisos de escritura. Verificar en:
```
System > Administrators > [API Admin] > Acceso
```

### Error 404 Not Found

El recurso no existe. Verificar:
- Nombres de interfaces
- IDs de políticas
- Nombres de objetos

### Error 400 Bad Request

Parámetros inválidos. Verificar:
- Formato de IPs (ej: `192.168.1.1 255.255.255.0`)
- Campos requeridos
- Valores de enums

## Notas de Seguridad

- Almacenar el token de API de forma segura
- Usar HTTPS en producción (`FORTIGATE_VERIFY_SSL=true`)
- Limitar el acceso por IP en la configuración del FortiGate
- Rotar los tokens periódicamente

## Licencia

MIT License - Ver LICENSE para detalles.

## Autor

Desarrollado para integración con Model Context Protocol.

---

**Versión:** 2.0.0  
**Compatible con:** FortiGate OS v7.6+

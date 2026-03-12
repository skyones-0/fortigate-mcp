# FortiGate MCP V7.6

## Model Context Protocol para FortiGate V7.6

Un protocolo de contexto de modelo completo para FortiGate V7.6 que proporciona control total de todos los módulos de seguridad, validación de comandos con token, análisis detallado de cambios y función de rollback.

## Características

- **Autenticación segura** con tokens de API de FortiGate
- **Validación de comandos** antes de ejecución
- **Análisis detallado de cambios** con impacto evaluado
- **Función de rollback** para revertir cambios
- **Cobertura completa** de módulos de seguridad FortiGate V7.6
- **TypeScript** con tipos completos
- **Logging completo** de auditoría y operaciones

## Módulos Soportados

### Módulos de Seguridad UTM/NGFW

| Módulo | Descripción | Versión |
|--------|-------------|---------|
| **Antivirus** | Perfiles de antivirus, escaneo en tiempo real, cuarentena | V7.6 |
| **IPS** | Intrusion Prevention System, firmas, detección de anomalías | V7.6 |
| **Web Filter** | Filtrado de contenido web, categorías FortiGuard | V7.6 |
| **DNS Filter** | Filtrado DNS, bloqueo de dominios maliciosos | V7.6 |
| **Application Control** | Control de aplicaciones, firmas de aplicaciones | V7.6 |
| **CASB** | Cloud Access Security Broker para SaaS | V7.6 |
| **DLP** | Prevención de pérdida de datos | V7.6 |
| **File Filter** | Filtrado de archivos por tipo | V7.6 |
| **Email Filter** | Filtrado de spam y contenido de email | V7.6 |
| **Video Filter** | Filtrado de contenido de video (YouTube, Vimeo, etc.) | V7.6 |
| **VoIP** | Seguridad para tráfico VoIP/SIP | V7.6 |

### Módulos de Inspección Profunda (DPI)

| Módulo | Descripción | Versión |
|--------|-------------|---------|
| **SSL/SSH Inspection** | Deep Packet Inspection para SSL/TLS y SSH | V7.6 |
| **WAF** | Web Application Firewall | V7.6 |
| **Virtual Patch** | Parches virtuales para vulnerabilidades | V7.6 |
| **ICAP** | Integración con servidores ICAP | V7.6 |

### Módulos de Red y VPN

| Módulo | Descripción | Versión |
|--------|-------------|---------|
| **Firewall Policy** | Políticas de firewall IPv4/IPv6 | V7.6 |
| **NAT** | NAT, Virtual IPs, IP Pools | V7.6 |
| **IPsec VPN** | Túneles VPN IPsec, fase 1 y 2 | V7.6 |
| **SSL VPN** | VPN SSL con túnel y modo web | V7.6 |
| **ZTNA** | Zero Trust Network Access | V7.6 |
| **SD-WAN** | SD-WAN, zonas, servicios, SLA | V7.6 |
| **Routing** | Rutas estáticas, dinámicas (OSPF, BGP) | V7.6 |

### Módulos de Sistema

| Módulo | Descripción | Versión |
|--------|-------------|---------|
| **Interfaces** | Configuración de interfaces físicas y VLANs | V7.6 |
| **HA** | Alta disponibilidad, clustering | V7.6 |
| **VDOM** | Virtual Domains | V7.6 |
| **Administradores** | Usuarios administradores, perfiles de acceso | V7.6 |
| **Logging** | Configuración de logs, FortiAnalyzer, syslog | V7.6 |
| **SNMP** | Configuración SNMP | V7.6 |
| **Certificates** | Gestión de certificados | V7.6 |
| **DHCP** | Servidores DHCP | V7.6 |

### Módulos de Gestión de Dispositivos

| Módulo | Descripción | Versión |
|--------|-------------|---------|
| **Switch Controller** | Gestión de FortiSwitches | V7.6 |
| **Wireless Controller** | Gestión de FortiAPs y WLANs | V7.6 |
| **FortiExtender** | Gestión de FortiExtenders | V7.6 |

## Instalación

```bash
npm install fortigate-mcp-v7.6
```

## Uso Rápido

```typescript
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

// Configuración de conexión
const config = {
  host: '192.168.1.99',
  port: 443,
  token: 'tu-api-token-aqui',
  https: true,
  verifySsl: false,
  vdom: 'root'
};

// Inicializar MCP
const mcp = new FortiGateMCP(config);

// Verificar conectividad
const connected = await mcp.checkConnectivity();
console.log(`Conectado: ${connected}`);

// Obtener información del sistema
const info = await mcp.getSystemInfo();
console.log(`FortiOS ${info.version} - ${info.hostname}`);
```

## Configuración

### Crear un Token de API en FortiGate

1. Acceder a **System > Administrators**
2. Crear un nuevo administrador tipo **REST API**
3. Asignar un **Admin Profile** con los permisos necesarios
4. Guardar y copiar el token generado

### Configuración de Permisos

| Funcionalidad | Permisos Requeridos |
|---------------|---------------------|
| Lectura de configuración | `read` en los módulos correspondientes |
| Modificación de configuración | `read-write` en los módulos correspondientes |
| Monitoreo | `read` en Log & Report |
| Administración del sistema | `read-write` en System |

## Módulos de Seguridad

### Antivirus

```typescript
// Crear un perfil de antivirus
const profile = await mcp.antivirus.createProfile({
  name: 'AV-Profile-Corporativo',
  inspection_mode: 'flow',
  ftgd_analytics: 'suspicious',
  http: {
    av_scan: 'enable',
    av_block: 'enable',
    av_quarantine: 'enable'
  },
  ftp: {
    av_scan: 'enable',
    av_block: 'enable'
  }
});

// Obtener perfiles existentes
const profiles = await mcp.antivirus.getProfiles();

// Actualizar un perfil
await mcp.antivirus.updateProfile('AV-Profile-Corporativo', {
  ftgd_analytics: 'everything'
});

// Eliminar un perfil
await mcp.antivirus.deleteProfile('AV-Profile-Corporativo');

// Obtener logs de detección
const logs = await mcp.antivirus.getDetectionLogs({
  since: '2024-01-01',
  limit: 100
});

// Actualizar base de datos
await mcp.antivirus.updateDatabase();
```

### IPS (Intrusion Prevention System)

```typescript
// Crear un sensor IPS
const sensor = await mcp.ips.createSensor({
  name: 'IPS-Corporativo',
  comment: 'Sensor IPS para red corporativa',
  entries: [
    {
      id: 1,
      severity: ['critical', 'high'],
      action: 'block',
      status: 'enable',
      log: 'enable'
    },
    {
      id: 2,
      severity: ['medium'],
      action: 'monitor',
      status: 'enable',
      log: 'enable'
    }
  ]
});

// Agregar una entrada al sensor
await mcp.ips.addEntry('IPS-Corporativo', {
  id: 3,
  protocol: ['TCP'],
  action: 'block',
  status: 'enable'
});

// Configurar escaneo de botnet
await mcp.ips.setBotnetScanning('IPS-Corporativo', 'block');

// Obtener intrusiones detectadas
const intrusions = await mcp.ips.getDetectedIntrusions({
  since: '2024-01-01',
  limit: 100
});
```

### Web Filter

```typescript
// Crear un perfil de filtrado web
const profile = await mcp.webfilter.createProfile({
  name: 'WF-Corporativo',
  inspection_mode: 'flow',
  ftgd_wf: {
    filters: [
      {
        id: 1,
        category: 26, // Adult Material
        action: 'block',
        log: 'enable'
      },
      {
        id: 2,
        category: 61, // Malicious Websites
        action: 'block',
        log: 'enable'
      }
    ]
  }
});

// Agregar filtro de categoría
await mcp.webfilter.addFortiguardFilter('WF-Corporativo', {
  id: 3,
  category: 88, // Spam
  action: 'block',
  log: 'enable'
});

// Configurar logging
await mcp.webfilter.setUrlLogging('WF-Corporativo', 'enable', 'enable');

// Obtener URLs bloqueadas
const blocked = await mcp.webfilter.getBlockedUrls({
  limit: 100
});
```

### CASB (Cloud Access Security Broker)

```typescript
// Crear un perfil CASB para Microsoft 365
const profile = await mcp.casb.createMicrosoft365Profile('CASB-M365', {
  blockUpload: false,
  blockDownload: true,
  blockShare: true,
  allowedTenants: ['miempresa.com', 'miempresa.onmicrosoft.com']
});

// Crear un perfil CASB para Google Workspace
const googleProfile = await mcp.casb.createGoogleWorkspaceProfile('CASB-Google', {
  blockUpload: true,
  allowedDomains: ['miempresa.com']
});

// Agregar una aplicación SaaS
await mcp.casb.addSaasApplication('CASB-M365', {
  name: 'dropbox',
  status: 'enable',
  default_action: 'block',
  log: 'enable'
});

// Obtener eventos de CASB
const events = await mcp.casb.getEvents({
  since: '2024-01-01',
  limit: 100
});

// Obtener violaciones de políticas
const violations = await mcp.casb.getPolicyViolations();
```

### SSL/SSH Inspection (DPI)

```typescript
// Crear un perfil de deep inspection
const profile = await mcp.sslInspection.createDeepInspectionProfile(
  'DPI-Profundo',
  'Mi-Certificado-CA'
);

// Crear un perfil de certificate inspection
const certProfile = await mcp.sslInspection.createCertificateInspectionProfile(
  'DPI-Certificado'
);

// Configurar inspección HTTPS
await mcp.sslInspection.setHttpsInspectionMode('DPI-Profundo', 'deep-inspection');

// Agregar exención por dirección
await mcp.sslInspection.addAddressExemption('DPI-Profundo', [
  '10.0.0.0/8',
  '192.168.1.0/24'
]);

// Agregar exención por FQDN wildcard
await mcp.sslInspection.addWildcardFqdnExemption('DPI-Profundo', [
  '*.banco.com',
  '*.salud.gob'
]);

// Configurar versiones SSL/TLS
await mcp.sslInspection.setSslVersions(
  'DPI-Profundo',
  'https',
  'tls-1.2',
  'tls-1.3'
);

// Obtener anomalías SSL detectadas
const anomalies = await mcp.sslInspection.getSslAnomalies();
```

## Validación de Comandos

```typescript
// Validar un comando antes de ejecutarlo
const validation = mcp.getCommandValidator().validateCommand(
  'config firewall policy',
  {
    module: 'firewall',
    operation: 'update',
    vdom: 'root'
  }
);

if (!validation.valid) {
  console.error('Errores:', validation.errors);
  console.warn('Advertencias:', validation.warnings);
}

// Validar una operación de API
const apiValidation = mcp.getCommandValidator().validateApiOperation(
  'POST',
  '/api/v2/cmdb/firewall/policy',
  { name: 'Nueva-Politica', action: 'accept' },
  { module: 'firewall', operation: 'create' }
);

// Validar un perfil de seguridad
const profileValidation = mcp.getCommandValidator().validateSecurityProfile(
  { name: 'Test', inspection_mode: 'flow' },
  'antivirus'
);

// Validar una política de firewall
const policyValidation = mcp.getCommandValidator().validateFirewallPolicy({
  name: 'Politica-Test',
  srcintf: [{ name: 'port1' }],
  dstintf: [{ name: 'port2' }],
  srcaddr: [{ name: 'all' }],
  dstaddr: [{ name: 'all' }],
  action: 'accept',
  service: [{ name: 'HTTP' }]
});
```

## Análisis de Cambios

```typescript
// Los cambios se registran automáticamente al usar los módulos

// Obtener todos los cambios
const allChanges = mcp.getChangeAnalyzer().getAllChanges();

// Obtener cambios por módulo
const firewallChanges = mcp.getChangeAnalyzer().getChangesByModule('firewall');

// Obtener cambios por operación
const creations = mcp.getChangeAnalyzer().getChangesByOperation('create');

// Analizar un cambio específico
const analysis = mcp.getChangeAnalyzer().analyzeChange(changeId);
console.log(`Impacto: ${analysis?.impact.level}`);
console.log(`Descripción: ${analysis?.impact.description}`);
console.log(`Recursos afectados: ${analysis?.impact.affectedResources}`);

// Generar un diff entre estados
const diff = mcp.getChangeAnalyzer().generateDiff(oldState, newState);

// Generar un informe de cambios
const report = mcp.getChangeAnalyzer().generateReport(
  new Date('2024-01-01'),
  new Date()
);

// Exportar cambios a JSON
const jsonExport = mcp.getChangeAnalyzer().exportToJson();

// Obtener estadísticas
const stats = mcp.getChangeAnalyzer().getStatistics();
console.log(`Total cambios: ${stats.totalChanges}`);
console.log(`Por módulo:`, stats.changesByModule);
```

## Función de Rollback

```typescript
// Crear un plan de rollback
const plan = await mcp.getRollbackManager().createRollbackPlan(changeId);
console.log(`Pasos: ${plan?.steps.length}`);
console.log(`Tiempo estimado: ${plan?.estimatedTime}s`);
console.log(`Riesgo: ${plan?.risk}`);

// Previsualizar un rollback
const preview = await mcp.getRollbackManager().previewRollback(changeId);
console.log(`Análisis:`, preview.analysis);

// Verificar si un cambio puede hacer rollback
const canRollback = mcp.getRollbackManager().canRollback(changeId);

// Ejecutar un rollback (dry run)
const dryRunResult = await mcp.getRollbackManager().executeRollback(changeId, {
  dryRun: true
});

// Ejecutar un rollback real
const result = await mcp.getRollbackManager().executeRollback(changeId, {
  dryRun: false,
  skipVerification: false,
  timeout: 300000 // 5 minutos
});

if (result.success) {
  console.log('Rollback exitoso:', result.message);
  console.log('Detalles:', result.details);
} else {
  console.error('Rollback fallido:', result.error);
}

// Ejecutar rollback de múltiples cambios
const batchResults = await mcp.getRollbackManager().executeBatchRollback(
  [changeId1, changeId2, changeId3],
  { stopOnError: true }
);

// Obtener historial de rollbacks
const history = mcp.getRollbackManager().getRollbackHistory();

// Generar informe de rollbacks
const rollbackReport = mcp.getRollbackManager().generateReport();
```

## Gestión de Tokens

```typescript
// Validar un token
const tokenValidation = mcp.getTokenValidator().validate(token);
if (!tokenValidation.valid) {
  console.error('Token inválido:', tokenValidation.errors);
}

// Obtener estadísticas del token
const tokenStats = mcp.getTokenValidator().getTokenStats(token);
console.log(`Entropía: ${tokenStats.entropy}`);
console.log(`Caracteres únicos: ${tokenStats.uniqueChars}`);

// Máscara el token para logging seguro
const masked = mcp.getTokenValidator().maskToken(token);
console.log(`Token: ${masked}`); // muestra: abcd****wxyz

// Actualizar el token
mcp.updateToken('nuevo-token-aqui');
```

## Monitoreo y Logs

```typescript
// Obtener estadísticas del sistema
const health = await mcp.getHealthStatus();
const resources = await mcp.getResourceStats();

// Obtener estado de interfaces
const interfaces = await mcp.getInterfaceStatus();

// Obtener estadísticas de sesiones
const sessions = await mcp.getSessionStats();

// Obtener estadísticas de políticas
const policies = await mcp.getPolicyStats();

// Generar informe del sistema
const systemReport = await mcp.generateSystemReport();

// Obtener estadísticas de API
const apiStats = mcp.getApiStats();
console.log(`Solicitudes: ${apiStats.requestCount}`);
```

## Configuración Avanzada

### Cambiar VDOM

```typescript
// Cambiar a un VDOM específico
mcp.setVdom('cliente-a');

// Todas las operaciones subsiguientes usarán este VDOM
const policies = await mcp.firewall.getPolicies();

// Volver al VDOM root
mcp.setVdom('root');
```

### Manejo de Errores

```typescript
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

try {
  const mcp = new FortiGateMCP(config);
  
  // Verificar conectividad primero
  const connected = await mcp.checkConnectivity();
  if (!connected) {
    throw new Error('No se pudo conectar al FortiGate');
  }
  
  // Operaciones...
  
} catch (error) {
  if (error.message.includes('401')) {
    console.error('Error de autenticación - verifique el token');
  } else if (error.message.includes('403')) {
    console.error('Acceso denegado - verifique permisos');
  } else if (error.message.includes('404')) {
    console.error('Recurso no encontrado');
  } else {
    console.error('Error:', error.message);
  }
}
```

### Logging

Los logs se almacenan en el directorio `logs/`:

- `combined.log` - Logs generales
- `error.log` - Errores
- `audit.log` - Auditoría de cambios
- `rollback.log` - Operaciones de rollback
- `validation.log` - Validaciones

```typescript
import { logger, auditLogger } from 'fortigate-mcp-v7.6';

// Agregar logs personalizados
logger.info('Operación completada', { detalles: '...' });
auditLogger.info('Cambio importante realizado', { cambio: '...' });
```

## API Reference

### FortiGateMCP

| Método | Descripción |
|--------|-------------|
| `checkConnectivity()` | Verifica conexión con FortiGate |
| `getSystemInfo()` | Obtiene información del sistema |
| `getVersion()` | Obtiene versión de FortiOS |
| `setVdom(vdom)` | Cambia el VDOM actual |
| `getCurrentVdom()` | Obtiene el VDOM actual |
| `updateToken(token)` | Actualiza el token de autenticación |
| `generateSystemReport()` | Genera informe completo |
| `getHealthStatus()` | Obtiene estado de salud |
| `getResourceStats()` | Obtiene estadísticas de recursos |

### Módulos

Cada módulo proporciona métodos CRUD estándar:

| Método | Descripción |
|--------|-------------|
| `getAll(params?)` | Obtiene todos los recursos |
| `getById(id)` | Obtiene un recurso específico |
| `create(data)` | Crea un nuevo recurso |
| `update(id, data)` | Actualiza un recurso |
| `delete(id)` | Elimina un recurso |
| `clone(id, newName)` | Clona un recurso |
| `exists(id)` | Verifica si existe un recurso |

## Requisitos

- Node.js >= 18.0.0
- FortiGate con FortiOS V7.6
- Token de API de FortiGate

## Dependencias

- axios: ^1.6.0
- zod: ^3.22.4
- winston: ^3.11.0
- crypto-js: ^4.2.0
- uuid: ^9.0.1
- date-fns: ^2.30.0

## Licencia

MIT

## Soporte

Para reportar problemas o solicitar características, por favor usar el issue tracker del proyecto.

## Changelog

### v1.0.0
- Lanzamiento inicial
- Soporte completo para FortiOS V7.6
- Todos los módulos de seguridad implementados
- Sistema de validación de comandos
- Análisis de cambios con impacto
- Función de rollback completa

---

**Nota**: Este MCP está diseñado para administradores de FortiGate con conocimientos de redes y seguridad. Siempre realice pruebas en un entorno de laboratorio antes de implementar cambios en producción.

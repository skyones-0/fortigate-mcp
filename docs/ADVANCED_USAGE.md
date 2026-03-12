# Uso Avanzado de FortiGate MCP V7.6

## Tabla de Contenidos

1. [Configuración Multi-VDOM](#configuración-multi-vdom)
2. [Gestión de Perfiles de Seguridad Completos](#gestión-de-perfiles-de-seguridad-completos)
3. [Automatización de Políticas de Firewall](#automatización-de-políticas-de-firewall)
4. [Monitoreo y Alertas](#monitoreo-y-alertas)
5. [Integración con CI/CD](#integración-con-cicd)
6. [Backup y Restore](#backup-y-restore)
7. [Gestión de Certificados](#gestión-de-certificados)
8. [Configuración de VPN](#configuración-de-vpn)
9. [SD-WAN Avanzado](#sd-wan-avanzado)
10. [Troubleshooting](#troubleshooting)

## Configuración Multi-VDOM

### Trabajar con múltiples VDOMs

```typescript
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

const mcp = new FortiGateMCP({
  host: '192.168.1.99',
  token: 'tu-token',
  vdom: 'root'
});

// Listar todos los VDOMs
async function listVdoms() {
  const vdoms = await mcp.client.get('/api/v2/cmdb/system/vdom');
  return vdoms.results;
}

// Cambiar entre VDOMs
async function configureMultipleVdoms() {
  // Configurar en VDOM root
  mcp.setVdom('root');
  await mcp.firewall.createPolicy({
    name: 'Root-Policy',
    srcintf: [{ name: 'port1' }],
    dstintf: [{ name: 'port2' }],
    srcaddr: [{ name: 'all' }],
    dstaddr: [{ name: 'all' }],
    action: 'accept',
    service: [{ name: 'ALL' }]
  });

  // Configurar en VDOM cliente-a
  mcp.setVdom('cliente-a');
  await mcp.firewall.createPolicy({
    name: 'ClienteA-Policy',
    srcintf: [{ name: 'port3' }],
    dstintf: [{ name: 'port4' }],
    srcaddr: [{ name: 'all' }],
    dstaddr: [{ name: 'all' }],
    action: 'accept',
    service: [{ name: 'HTTP' }],
    av_profile: 'default'
  });

  // Volver a root
  mcp.setVdom('root');
}

// Obtener estadísticas por VDOM
async function getVdomStats() {
  const changesByVdom = mcp.getChangeAnalyzer().getChangesByVdom('cliente-a');
  console.log(`Cambios en cliente-a: ${changesByVdom.length}`);
}
```

## Gestión de Perfiles de Seguridad Completos

### Crear un perfil de seguridad completo

```typescript
async function createCompleteSecurityProfile(profileName: string) {
  // 1. Crear perfil de antivirus
  await mcp.antivirus.createProfile({
    name: `${profileName}-AV`,
    inspection_mode: 'flow',
    ftgd_analytics: 'suspicious',
    http: { av_scan: 'enable', av_block: 'enable' },
    ftp: { av_scan: 'enable', av_block: 'enable' },
    smtp: { av_scan: 'enable', av_block: 'enable' },
    pop3: { av_scan: 'enable', av_block: 'enable' },
    imap: { av_scan: 'enable', av_block: 'enable' }
  });

  // 2. Crear sensor IPS
  await mcp.ips.createSensor({
    name: `${profileName}-IPS`,
    entries: [
      {
        id: 1,
        severity: ['critical', 'high'],
        action: 'block',
        status: 'enable',
        log: 'enable',
        log_packet: 'enable'
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

  // 3. Crear perfil de filtrado web
  await mcp.webfilter.createProfile({
    name: `${profileName}-WF`,
    inspection_mode: 'flow',
    ftgd_wf: {
      filters: [
        { id: 1, category: 26, action: 'block', log: 'enable' },
        { id: 2, category: 61, action: 'block', log: 'enable' },
        { id: 3, category: 86, action: 'block', log: 'enable' }
      ]
    }
  });

  // 4. Crear perfil de filtrado DNS
  await mcp.client.post('/api/v2/cmdb/dnsfilter/profile', {
    name: `${profileName}-DNS`,
    ftgd_dns: {
      filters: [
        { id: 1, category: 88, action: 'block', log: 'enable' }
      ]
    }
  });

  // 5. Crear perfil de control de aplicaciones
  await mcp.client.post('/api/v2/cmdb/application/list', {
    name: `${profileName}-APP`,
    entries: [
      {
        id: 1,
        category: [5], // Business
        action: 'pass',
        log: 'enable'
      },
      {
        id: 2,
        category: [15], // P2P
        action: 'block',
        log: 'enable'
      }
    ]
  });

  // 6. Crear grupo de perfiles
  await mcp.client.post('/api/v2/cmdb/firewall/profile-group', {
    name: profileName,
    av_profile: `${profileName}-AV`,
    ips_sensor: `${profileName}-IPS`,
    webfilter_profile: `${profileName}-WF`,
    dnsfilter_profile: `${profileName}-DNS`,
    application_list: `${profileName}-APP`,
    ssl_ssh_profile: 'certificate-inspection'
  });

  console.log(`✓ Perfil de seguridad completo creado: ${profileName}`);
}
```

## Automatización de Políticas de Firewall

### Crear políticas masivamente

```typescript
interface PolicyTemplate {
  name: string;
  srcintf: string;
  dstintf: string;
  srcaddr: string;
  dstaddr: string;
  service: string;
  action: 'accept' | 'deny';
  nat?: 'enable' | 'disable';
  profileGroup?: string;
}

async function createPoliciesFromTemplate(
  policies: PolicyTemplate[]
) {
  const results = [];

  for (const policy of policies) {
    try {
      const newPolicy: any = {
        name: policy.name,
        srcintf: [{ name: policy.srcintf }],
        dstintf: [{ name: policy.dstintf }],
        srcaddr: [{ name: policy.srcaddr }],
        dstaddr: [{ name: policy.dstaddr }],
        service: [{ name: policy.service }],
        action: policy.action,
        schedule: 'always',
        logtraffic: 'utm'
      };

      if (policy.nat) {
        newPolicy.nat = policy.nat;
      }

      if (policy.profileGroup) {
        newPolicy.utm_status = 'enable';
        newPolicy.profile_group = policy.profileGroup;
      }

      const result = await mcp.client.post(
        '/api/v2/cmdb/firewall/policy',
        newPolicy
      );

      results.push({ success: true, name: policy.name, result });
    } catch (error) {
      results.push({ 
        success: false, 
        name: policy.name, 
        error: (error as Error).message 
      });
    }
  }

  return results;
}

// Uso
const policies: PolicyTemplate[] = [
  {
    name: 'LAN-to-WAN',
    srcintf: 'port1',
    dstintf: 'port2',
    srcaddr: 'LAN-Subnet',
    dstaddr: 'all',
    service: 'HTTP HTTPS',
    action: 'accept',
    nat: 'enable',
    profileGroup: 'Corporate-Security'
  },
  {
    name: 'DMZ-to-WAN',
    srcintf: 'port3',
    dstintf: 'port2',
    srcaddr: 'DMZ-Subnet',
    dstaddr: 'all',
    service: 'DNS HTTP HTTPS',
    action: 'accept',
    nat: 'enable'
  }
];

const results = await createPoliciesFromTemplate(policies);
```

## Monitoreo y Alertas

### Sistema de monitoreo continuo

```typescript
class FortiGateMonitor {
  private mcp: FortiGateMCP;
  private alertThresholds: any;

  constructor(mcp: FortiGateMCP) {
    this.mcp = mcp;
    this.alertThresholds = {
      cpu: 80,
      memory: 85,
      sessions: 1000000
    };
  }

  async checkSystemHealth(): Promise<any> {
    const health = await this.mcp.getHealthStatus();
    const resources = await this.mcp.getResourceStats();
    const sessions = await this.mcp.getSessionStats();

    const alerts = [];

    // Verificar CPU
    if (resources.results?.[0]?.cpu > this.alertThresholds.cpu) {
      alerts.push({
        severity: 'high',
        component: 'CPU',
        message: `CPU usage is ${resources.results[0].cpu}%`,
        threshold: this.alertThresholds.cpu
      });
    }

    // Verificar memoria
    if (resources.results?.[0]?.mem > this.alertThresholds.memory) {
      alerts.push({
        severity: 'high',
        component: 'Memory',
        message: `Memory usage is ${resources.results[0].mem}%`,
        threshold: this.alertThresholds.memory
      });
    }

    // Verificar sesiones
    if (sessions.results?.[0]?.session_count > this.alertThresholds.sessions) {
      alerts.push({
        severity: 'warning',
        component: 'Sessions',
        message: `Session count is ${sessions.results[0].session_count}`,
        threshold: this.alertThresholds.sessions
      });
    }

    return {
      timestamp: new Date(),
      health: health.results?.[0],
      resources: resources.results?.[0],
      sessions: sessions.results?.[0],
      alerts
    };
  }

  async monitorSecurityEvents(timeWindow: number = 3600): Promise<any> {
    const since = new Date(Date.now() - timeWindow * 1000).toISOString();

    const [
      virusDetections,
      intrusions,
      blockedUrls,
      appControl
    ] = await Promise.all([
      this.mcp.antivirus.getDetectionLogs({ since, limit: 100 }),
      this.mcp.ips.getDetectedIntrusions({ since, limit: 100 }),
      this.mcp.webfilter.getBlockedUrls({ since, limit: 100 }),
      this.mcp.client.get('/api/v2/monitor/application/control', { since, limit: 100 })
    ]);

    return {
      timestamp: new Date(),
      timeWindow,
      events: {
        viruses: virusDetections.size,
        intrusions: intrusions.size,
        blockedUrls: blockedUrls.size,
        appControl: appControl.size
      },
      details: {
        virusDetections: virusDetections.results,
        intrusions: intrusions.results,
        blockedUrls: blockedUrls.results
      }
    };
  }

  async generateDailyReport(): Promise<string> {
    const health = await this.checkSystemHealth();
    const security = await this.monitorSecurityEvents(86400);

    let report = '=== DAILY FORTIGATE REPORT ===\n\n';
    report += `Date: ${new Date().toISOString()}\n\n`;

    report += '=== SYSTEM HEALTH ===\n';
    report += `CPU: ${health.resources?.cpu}%\n`;
    report += `Memory: ${health.resources?.mem}%\n`;
    report += `Sessions: ${health.sessions?.session_count}\n`;

    if (health.alerts.length > 0) {
      report += '\n=== ALERTS ===\n';
      health.alerts.forEach((alert: any) => {
        report += `[${alert.severity.toUpperCase()}] ${alert.component}: ${alert.message}\n`;
      });
    }

    report += '\n=== SECURITY EVENTS (24h) ===\n';
    report += `Virus Detections: ${security.events.viruses}\n`;
    report += `Intrusions: ${security.events.intrusions}\n`;
    report += `Blocked URLs: ${security.events.blockedUrls}\n`;
    report += `App Control Events: ${security.events.appControl}\n`;

    return report;
  }
}

// Uso
const monitor = new FortiGateMonitor(mcp);

// Verificar salud cada 5 minutos
setInterval(async () => {
  const health = await monitor.checkSystemHealth();
  if (health.alerts.length > 0) {
    console.error('ALERTS:', health.alerts);
    // Enviar notificación (email, Slack, etc.)
  }
}, 300000);
```

## Integración con CI/CD

### Pipeline de despliegue

```typescript
// deploy-config.ts
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

interface DeploymentConfig {
  environment: 'dev' | 'staging' | 'prod';
  policies: any[];
  profiles: any[];
  validateOnly?: boolean;
}

async function deployConfiguration(config: DeploymentConfig) {
  const mcp = new FortiGateMCP({
    host: process.env[`FORTIGATE_${config.environment.toUpperCase()}_HOST`]!,
    token: process.env[`FORTIGATE_${config.environment.toUpperCase()}_TOKEN`]!,
    vdom: process.env[`FORTIGATE_${config.environment.toUpperCase()}_VDOM`] || 'root'
  });

  // Validar configuración antes de desplegar
  console.log('Validando configuración...');
  for (const policy of config.policies) {
    const validation = mcp.getCommandValidator().validateFirewallPolicy(policy);
    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map((e: any) => e.message).join(', ')}`);
    }
  }

  if (config.validateOnly) {
    console.log('✓ Validación exitosa (dry-run)');
    return;
  }

  // Crear punto de rollback
  console.log('Creando punto de restauración...');
  const backup = await mcp.backupConfiguration();

  try {
    // Desplegar perfiles
    console.log('Desplegando perfiles de seguridad...');
    for (const profile of config.profiles) {
      await deployProfile(mcp, profile);
    }

    // Desplegar políticas
    console.log('Desplegando políticas de firewall...');
    for (const policy of config.policies) {
      await deployPolicy(mcp, policy);
    }

    console.log('✓ Despliegue completado exitosamente');

  } catch (error) {
    console.error('Error en despliegue:', error);
    console.log('Iniciando rollback...');
    
    // Rollback automático
    // Implementar lógica de rollback según sea necesario
    
    throw error;
  }
}

async function deployProfile(mcp: FortiGateMCP, profile: any) {
  const existing = await mcp.antivirus.getProfile(profile.name);
  
  if (existing) {
    console.log(`Actualizando perfil: ${profile.name}`);
    await mcp.antivirus.updateProfile(profile.name, profile);
  } else {
    console.log(`Creando perfil: ${profile.name}`);
    await mcp.antivirus.createProfile(profile);
  }
}

async function deployPolicy(mcp: FortiGateMCP, policy: any) {
  // Buscar política existente
  const policies = await mcp.client.get('/api/v2/cmdb/firewall/policy', {
    filter: `name==${policy.name}`
  });

  if (policies.results?.length > 0) {
    console.log(`Actualizando política: ${policy.name}`);
    const policyId = policies.results[0].policyid;
    await mcp.client.put(`/api/v2/cmdb/firewall/policy/${policyId}`, policy);
  } else {
    console.log(`Creando política: ${policy.name}`);
    await mcp.client.post('/api/v2/cmdb/firewall/policy', policy);
  }
}

// Uso en pipeline
const config: DeploymentConfig = {
  environment: 'staging',
  validateOnly: process.env.VALIDATE_ONLY === 'true',
  profiles: [
    {
      name: 'Staging-AV',
      inspection_mode: 'flow',
      http: { av_scan: 'enable' }
    }
  ],
  policies: [
    {
      name: 'Staging-LAN-to-WAN',
      srcintf: [{ name: 'port1' }],
      dstintf: [{ name: 'port2' }],
      srcaddr: [{ name: 'all' }],
      dstaddr: [{ name: 'all' }],
      action: 'accept',
      service: [{ name: 'HTTP HTTPS' }],
      nat: 'enable'
    }
  ]
};

deployConfiguration(config)
  .then(() => process.exit(0))
  .catch(() => process.exit(1));
```

## Backup y Restore

### Sistema de backup automatizado

```typescript
class FortiGateBackup {
  private mcp: FortiGateMCP;
  private backupPath: string;

  constructor(mcp: FortiGateMCP, backupPath: string) {
    this.mcp = mcp;
    this.backupPath = backupPath;
  }

  async createBackup(): Promise<string> {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `fortigate-backup-${timestamp}.json`;

    // Backup de configuración completa
    const config = await this.mcp.backupConfiguration();

    // Backup de perfiles de seguridad
    const securityProfiles = await this.backupSecurityProfiles();

    // Backup de políticas
    const policies = await this.backupPolicies();

    const fullBackup = {
      timestamp: new Date().toISOString(),
      system: JSON.parse(config),
      securityProfiles,
      policies
    };

    // Guardar a archivo
    const fs = require('fs');
    const path = require('path');
    const fullPath = path.join(this.backupPath, filename);
    
    fs.writeFileSync(fullPath, JSON.stringify(fullBackup, null, 2));

    console.log(`✓ Backup creado: ${fullPath}`);
    return fullPath;
  }

  private async backupSecurityProfiles(): Promise<any> {
    const [
      antivirus,
      ips,
      webfilter,
      dnsfilter
    ] = await Promise.all([
      this.mcp.antivirus.getProfiles(),
      this.mcp.ips.getSensors(),
      this.mcp.webfilter.getProfiles(),
      this.mcp.client.get('/api/v2/cmdb/dnsfilter/profile')
    ]);

    return {
      antivirus: antivirus.results,
      ips: ips.results,
      webfilter: webfilter.results,
      dnsfilter: dnsfilter.results
    };
  }

  private async backupPolicies(): Promise<any> {
    const policies = await this.mcp.client.get('/api/v2/cmdb/firewall/policy');
    const vips = await this.mcp.client.get('/api/v2/cmdb/firewall/vip');
    const ippools = await this.mcp.client.get('/api/v2/cmdb/firewall/ippool');

    return {
      policies: policies.results,
      vips: vips.results,
      ippools: ippools.results
    };
  }

  async restoreFromBackup(backupFile: string): Promise<void> {
    const fs = require('fs');
    const backup = JSON.parse(fs.readFileSync(backupFile, 'utf8'));

    console.log(`Restaurando desde: ${backupFile}`);
    console.log(`Fecha del backup: ${backup.timestamp}`);

    // Confirmación interactiva o flag --force
    // ...

    // Restaurar perfiles de seguridad
    await this.restoreSecurityProfiles(backup.securityProfiles);

    // Restaurar políticas
    await this.restorePolicies(backup.policies);

    console.log('✓ Restauración completada');
  }

  private async restoreSecurityProfiles(profiles: any): Promise<void> {
    // Implementar lógica de restauración
    // Considerar merge vs overwrite
  }

  private async restorePolicies(policies: any): Promise<void> {
    // Implementar lógica de restauración
    // Considerar manejo de dependencias
  }
}
```

## Troubleshooting

### Diagnóstico de problemas comunes

```typescript
class FortiGateDiagnostics {
  private mcp: FortiGateMCP;

  constructor(mcp: FortiGateMCP) {
    this.mcp = mcp;
  }

  async diagnoseConnectivity(): Promise<any> {
    const results = {
      timestamp: new Date(),
      tests: [] as any[]
    };

    // Test 1: Conectividad básica
    try {
      const connected = await this.mcp.checkConnectivity();
      results.tests.push({
        name: 'Basic Connectivity',
        status: connected ? 'pass' : 'fail',
        details: connected ? 'Connected successfully' : 'Connection failed'
      });
    } catch (error) {
      results.tests.push({
        name: 'Basic Connectivity',
        status: 'fail',
        details: (error as Error).message
      });
    }

    // Test 2: Autenticación
    try {
      const info = await this.mcp.getSystemInfo();
      results.tests.push({
        name: 'Authentication',
        status: 'pass',
        details: `Authenticated as ${info.hostname}`
      });
    } catch (error) {
      results.tests.push({
        name: 'Authentication',
        status: 'fail',
        details: (error as Error).message
      });
    }

    // Test 3: Permisos
    try {
      await this.mcp.client.get('/api/v2/cmdb/firewall/policy');
      results.tests.push({
        name: 'Policy Read Permission',
        status: 'pass'
      });
    } catch (error) {
      results.tests.push({
        name: 'Policy Read Permission',
        status: 'fail',
        details: (error as Error).message
      });
    }

    // Test 4: Estado de licencias
    try {
      const licenses = await this.mcp.client.get('/api/v2/monitor/system/fortiguard/status');
      results.tests.push({
        name: 'License Status',
        status: licenses.results?.[0]?.status === 'licensed' ? 'pass' : 'warning',
        details: licenses.results?.[0]
      });
    } catch (error) {
      results.tests.push({
        name: 'License Status',
        status: 'fail',
        details: (error as Error).message
      });
    }

    return results;
  }

  async diagnosePolicyIssues(policyId: number): Promise<any> {
    const policy = await this.mcp.client.get(`/api/v2/cmdb/firewall/policy/${policyId}`);
    const issues = [];

    if (!policy.results?.[0]) {
      return { error: 'Policy not found' };
    }

    const p = policy.results[0];

    // Verificar interfaces
    if (!p.srcintf || p.srcintf.length === 0) {
      issues.push({ severity: 'high', message: 'No source interface configured' });
    }
    if (!p.dstintf || p.dstintf.length === 0) {
      issues.push({ severity: 'high', message: 'No destination interface configured' });
    }

    // Verificar direcciones
    if (!p.srcaddr || p.srcaddr.length === 0) {
      issues.push({ severity: 'high', message: 'No source address configured' });
    }
    if (!p.dstaddr || p.dstaddr.length === 0) {
      issues.push({ severity: 'high', message: 'No destination address configured' });
    }

    // Verificar NAT
    if (p.nat === 'enable' && p.ippool === 'enable' && (!p.poolname || p.poolname.length === 0)) {
      issues.push({ severity: 'medium', message: 'NAT enabled with IP Pool but no pool specified' });
    }

    // Verificar perfiles de seguridad
    if (p.utm_status === 'enable' && !p.profile_group && !p.av_profile) {
      issues.push({ severity: 'low', message: 'UTM enabled but no security profiles configured' });
    }

    return {
      policy: p,
      issues,
      recommendations: this.generateRecommendations(issues)
    };
  }

  private generateRecommendations(issues: any[]): string[] {
    const recommendations = [];

    for (const issue of issues) {
      switch (issue.message) {
        case 'No source interface configured':
          recommendations.push('Configure a source interface for this policy');
          break;
        case 'No destination interface configured':
          recommendations.push('Configure a destination interface for this policy');
          break;
        case 'NAT enabled with IP Pool but no pool specified':
          recommendations.push('Either disable IP Pool or specify a valid IP Pool');
          break;
        case 'UTM enabled but no security profiles configured':
          recommendations.push('Configure security profiles or disable UTM');
          break;
      }
    }

    return recommendations;
  }
}
```

---

Para más información, consulte la documentación completa en el README principal.

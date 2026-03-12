/**
 * Ejemplo básico de uso de FortiGate MCP V7.6
 */

import { FortiGateMCP } from '../src/index';

async function main() {
  // Configuración de conexión
  const config = {
    host: process.env.FORTIGATE_HOST || '192.168.1.99',
    port: parseInt(process.env.FORTIGATE_PORT || '443'),
    token: process.env.FORTIGATE_TOKEN || 'tu-token-aqui',
    https: true,
    verifySsl: false,
    vdom: process.env.FORTIGATE_VDOM || 'root'
  };

  try {
    // Inicializar MCP
    console.log('Inicializando FortiGate MCP...');
    const mcp = new FortiGateMCP(config);

    // Verificar conectividad
    console.log('Verificando conectividad...');
    const connected = await mcp.checkConnectivity();
    
    if (!connected) {
      console.error('No se pudo conectar al FortiGate');
      process.exit(1);
    }
    
    console.log('✓ Conectado exitosamente');

    // Obtener información del sistema
    console.log('\n=== INFORMACIÓN DEL SISTEMA ===');
    const info = await mcp.getSystemInfo();
    console.log(`Hostname: ${info.hostname}`);
    console.log(`Versión: ${info.version}`);
    console.log(`Modelo: ${info.model}`);
    console.log(`Serial: ${info.serial}`);
    console.log(`Uptime: ${info.uptime}`);

    // Crear un perfil de antivirus
    console.log('\n=== CREANDO PERFIL DE ANTIVIRUS ===');
    try {
      const avProfile = await mcp.antivirus.createProfile({
        name: 'Ejemplo-AV-Profile',
        comment: 'Perfil de antivirus de ejemplo',
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
      console.log('✓ Perfil de antivirus creado');
    } catch (error) {
      console.log('Perfil ya existe o error:', (error as Error).message);
    }

    // Listar perfiles de antivirus
    console.log('\n=== PERFILES DE ANTIVIRUS ===');
    const avProfiles = await mcp.antivirus.getProfiles();
    console.log(`Total: ${avProfiles.size}`);
    avProfiles.results.slice(0, 5).forEach(p => {
      console.log(`  - ${p.name}`);
    });

    // Crear un sensor IPS
    console.log('\n=== CREANDO SENSOR IPS ===');
    try {
      const ipsSensor = await mcp.ips.createSensor({
        name: 'Ejemplo-IPS-Sensor',
        comment: 'Sensor IPS de ejemplo',
        entries: [
          {
            id: 1,
            severity: ['critical', 'high'],
            action: 'block',
            status: 'enable',
            log: 'enable'
          }
        ]
      });
      console.log('✓ Sensor IPS creado');
    } catch (error) {
      console.log('Sensor ya existe o error:', (error as Error).message);
    }

    // Listar sensores IPS
    console.log('\n=== SENSORES IPS ===');
    const ipsSensors = await mcp.ips.getSensors();
    console.log(`Total: ${ipsSensors.size}`);
    ipsSensors.results.slice(0, 5).forEach(s => {
      console.log(`  - ${s.name}`);
    });

    // Crear un perfil de filtrado web
    console.log('\n=== CREANDO PERFIL WEB FILTER ===');
    try {
      const wfProfile = await mcp.webfilter.createProfile({
        name: 'Ejemplo-WF-Profile',
        comment: 'Perfil de filtrado web de ejemplo',
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
      console.log('✓ Perfil de filtrado web creado');
    } catch (error) {
      console.log('Perfil ya existe o error:', (error as Error).message);
    }

    // Obtener estadísticas
    console.log('\n=== ESTADÍSTICAS ===');
    const changes = mcp.getChangeAnalyzer().getStatistics();
    console.log(`Cambios registrados: ${changes.totalChanges}`);
    console.log(`Rollback disponibles: ${changes.rollbackableChanges}`);

    // Generar informe
    console.log('\n=== GENERANDO INFORME ===');
    const report = await mcp.generateSystemReport();
    console.log(report);

    // Mostrar cambios recientes
    console.log('\n=== CAMBIOS RECIENTES ===');
    const recentChanges = mcp.getChangeAnalyzer().getAllChanges().slice(0, 5);
    recentChanges.forEach(c => {
      console.log(`[${c.timestamp.toISOString()}] ${c.module}/${c.resource} - ${c.operation}`);
    });

    console.log('\n✓ Ejemplo completado exitosamente');

  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

// Ejecutar si se llama directamente
if (require.main === module) {
  main();
}

export { main };

#!/usr/bin/env node
/**
 * Wrapper para el MCP FortiGate que asegura las variables de entorno
 */

// Cargar variables de entorno manualmente si no están presentes
const requiredEnv = {
  FORTIGATE_HOST: '172.28.20.1',
  FORTIGATE_API_TOKEN: 'qk4hzxz4jr48b035dz3jj9y1Qwj5sw',
  FORTIGATE_PORT: '443',
  FORTIGATE_HTTPS: 'true',
  FORTIGATE_VERIFY_SSL: 'false',
  FORTIGATE_VDOM: 'root',
};

for (const [key, value] of Object.entries(requiredEnv)) {
  if (!process.env[key]) {
    process.env[key] = value;
  }
}

// Importar y ejecutar el servidor MCP
import('./dist/index.js').catch(err => {
  console.error('Error al cargar el servidor MCP:', err);
  process.exit(1);
});

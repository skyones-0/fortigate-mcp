/**
 * Sistema de logging para FortiGate MCP
 */

import winston from 'winston';
import path from 'path';

const { combine, timestamp, printf, colorize, errors, json } = winston.format;

// Formato personalizado para consola
const consoleFormat = printf(({ level, message, timestamp, ...metadata }) => {
  let msg = `${timestamp} [${level}]: ${message}`;
  if (Object.keys(metadata).length > 0) {
    msg += ` ${JSON.stringify(metadata)}`;
  }
  return msg;
});

// Crear el logger
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'fortigate-mcp' },
  transports: [
    // Log a archivo en formato JSON
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'error.log'),
      level: 'error',
      format: combine(timestamp(), json())
    }),
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'combined.log'),
      format: combine(timestamp(), json())
    })
  ]
});

// Agregar transporte de consola en desarrollo
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: combine(
      colorize(),
      timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
      consoleFormat
    )
  }));
}

// Logger específico para auditoría de cambios
export const auditLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'fortigate-mcp-audit' },
  transports: [
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'audit.log'),
      format: combine(timestamp(), json())
    })
  ]
});

// Logger específico para rollback
export const rollbackLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'fortigate-mcp-rollback' },
  transports: [
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'rollback.log'),
      format: combine(timestamp(), json())
    })
  ]
});

// Logger específico para validaciones
export const validationLogger = winston.createLogger({
  level: 'info',
  defaultMeta: { service: 'fortigate-mcp-validation' },
  transports: [
    new winston.transports.File({
      filename: path.join(process.cwd(), 'logs', 'validation.log'),
      format: combine(timestamp(), json())
    })
  ]
});

export default logger;

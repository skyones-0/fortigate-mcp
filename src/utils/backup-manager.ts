/**
 * Sistema de gestión de backups para FortiGate
 * Maneja backups locales y remotos con metadata
 */

import { writeFile, readFile, mkdir, readdir, stat, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';
import type { FortiGateClient } from '../client/fortigate-client.js';

// Directorio de backups
const BACKUP_DIR = process.env.FORTIGATE_BACKUP_DIR || './backups';
const MAX_BACKUPS = parseInt(process.env.FORTIGATE_MAX_BACKUPS || '50');
const BACKUP_RETENTION_DAYS = parseInt(process.env.FORTIGATE_BACKUP_RETENTION || '30');

// Interfaz para metadata de backup
export interface BackupMetadata {
  id: string;
  filename: string;
  createdAt: string;
  hostname: string;
  serial: string;
  version: string;
  vdom: string;
  scope: 'global' | 'vdom';
  size: number;
  hash: string;
  description?: string;
  triggeredBy: string;
  autoBackup: boolean;
}

// Interfaz para resultado de backup
export interface BackupResult {
  success: boolean;
  backupId?: string;
  filename?: string;
  metadata?: BackupMetadata;
  error?: string;
}

// Interfaz para comparación de backups
export interface BackupComparison {
  differences: string[];
  added: string[];
  removed: string[];
  modified: string[];
  unchanged: string[];
}

/**
 * Inicializa el directorio de backups
 */
export async function initializeBackupSystem(): Promise<void> {
  if (!existsSync(BACKUP_DIR)) {
    await mkdir(BACKUP_DIR, { recursive: true });
  }
}

/**
 * Genera ID único para backup
 */
function generateBackupId(): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const random = Math.random().toString(36).substring(2, 8);
  return `backup-${timestamp}-${random}`;
}

/**
 * Calcula hash SHA256 de contenido
 */
function calculateHash(content: string): string {
  return createHash('sha256').update(content).digest('hex').substring(0, 16);
}

/**
 * Crea un backup de la configuración del FortiGate
 */
export async function createBackup(
  client: FortiGateClient,
  options: {
    scope?: 'global' | 'vdom';
    vdom?: string;
    description?: string;
    autoBackup?: boolean;
    triggeredBy?: string;
  } = {}
): Promise<BackupResult> {
  try {
    await initializeBackupSystem();

    const scope = options.scope || 'global';
    const vdom = options.vdom || 'root';
    const autoBackup = options.autoBackup ?? false;
    const triggeredBy = options.triggeredBy || 'manual';

    // Obtener información del sistema
    const systemStatus = await client.getSystemStatus();
    const hostname = systemStatus.hostname || 'unknown';
    const serial = systemStatus.serial || 'unknown';
    const version = systemStatus.version || 'unknown';

    // Crear backup usando la API
    const backupContent = await client.backupConfig(scope);

    // Generar nombre de archivo y metadata
    const backupId = generateBackupId();
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safeHostname = hostname.replace(/[^a-zA-Z0-9_-]/g, '_');
    const filename = `${safeHostname}_${serial}_${scope}_${timestamp}.conf`;

    // Calcular hash
    const hash = calculateHash(backupContent);

    // Crear metadata
    const metadata: BackupMetadata = {
      id: backupId,
      filename,
      createdAt: new Date().toISOString(),
      hostname,
      serial,
      version,
      vdom,
      scope,
      size: Buffer.byteLength(backupContent, 'utf8'),
      hash,
      description: options.description,
      triggeredBy,
      autoBackup,
    };

    // Guardar archivo de backup
    const backupPath = join(BACKUP_DIR, filename);
    await writeFile(backupPath, backupContent, 'utf8');

    // Guardar metadata
    const metadataPath = join(BACKUP_DIR, `${filename}.json`);
    await writeFile(metadataPath, JSON.stringify(metadata, null, 2), 'utf8');

    // Limpiar backups antiguos
    await cleanupOldBackups();

    // Limitar número de backups
    await enforceBackupLimit();

    return {
      success: true,
      backupId,
      filename,
      metadata,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error creating backup',
    };
  }
}

/**
 * Lista todos los backups disponibles
 */
export async function listBackups(
  options: {
    hostname?: string;
    serial?: string;
    scope?: 'global' | 'vdom';
    autoOnly?: boolean;
    limit?: number;
  } = {}
): Promise<BackupMetadata[]> {
  try {
    await initializeBackupSystem();

    const files = await readdir(BACKUP_DIR);
    const metadataFiles = files.filter(f => f.endsWith('.conf.json'));

    const backups: BackupMetadata[] = [];

    for (const file of metadataFiles) {
      try {
        const metadataPath = join(BACKUP_DIR, file);
        const content = await readFile(metadataPath, 'utf8');
        const metadata: BackupMetadata = JSON.parse(content);

        // Aplicar filtros
        if (options.hostname && metadata.hostname !== options.hostname) continue;
        if (options.serial && metadata.serial !== options.serial) continue;
        if (options.scope && metadata.scope !== options.scope) continue;
        if (options.autoOnly && !metadata.autoBackup) continue;

        backups.push(metadata);
      } catch {
        // Ignorar archivos corruptos
        continue;
      }
    }

    // Ordenar por fecha descendente
    backups.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    // Aplicar límite
    if (options.limit && options.limit > 0) {
      return backups.slice(0, options.limit);
    }

    return backups;
  } catch (error) {
    throw new Error(`Failed to list backups: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Obtiene un backup específico por ID
 */
export async function getBackup(backupId: string): Promise<{ metadata: BackupMetadata; content: string } | null> {
  try {
    const backups = await listBackups();
    const backup = backups.find(b => b.id === backupId);

    if (!backup) {
      return null;
    }

    const backupPath = join(BACKUP_DIR, backup.filename);
    const content = await readFile(backupPath, 'utf8');

    return { metadata: backup, content };
  } catch {
    return null;
  }
}

/**
 * Elimina un backup
 */
export async function deleteBackup(backupId: string): Promise<boolean> {
  try {
    const backups = await listBackups();
    const backup = backups.find(b => b.id === backupId);

    if (!backup) {
      return false;
    }

    // Eliminar archivo de backup
    const backupPath = join(BACKUP_DIR, backup.filename);
    if (existsSync(backupPath)) {
      await unlink(backupPath);
    }

    // Eliminar metadata
    const metadataPath = join(BACKUP_DIR, `${backup.filename}.json`);
    if (existsSync(metadataPath)) {
      await unlink(metadataPath);
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Restaura configuración desde un backup
 */
export async function restoreBackup(
  client: FortiGateClient,
  backupId: string,
  options: {
    scope?: 'global' | 'vdom';
    vdom?: string;
  } = {}
): Promise<{ success: boolean; error?: string }> {
  try {
    const backup = await getBackup(backupId);

    if (!backup) {
      return { success: false, error: 'Backup not found' };
    }

    // Verificar compatibilidad
    const systemStatus = await client.getSystemStatus();
    if (backup.metadata.serial !== systemStatus.serial) {
      return {
        success: false,
        error: `Backup serial ${backup.metadata.serial} does not match current device ${systemStatus.serial}`,
      };
    }

    // Realizar restore
    const scope = options.scope || backup.metadata.scope;
    await client.restoreConfig(backup.content, scope);

    return { success: true };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error during restore',
    };
  }
}

/**
 * Compara dos backups
 */
export async function compareBackups(
  backupId1: string,
  backupId2: string
): Promise<BackupComparison | null> {
  try {
    const backup1 = await getBackup(backupId1);
    const backup2 = await getBackup(backupId2);

    if (!backup1 || !backup2) {
      return null;
    }

    // Parsear configuraciones (simplificado)
    const config1 = parseConfigLines(backup1.content);
    const config2 = parseConfigLines(backup2.content);

    const added: string[] = [];
    const removed: string[] = [];
    const modified: string[] = [];
    const unchanged: string[] = [];

    // Encontrar diferencias
    const keys1 = Object.keys(config1);
    const keys2 = Object.keys(config2);

    for (const key of keys1) {
      if (!(key in config2)) {
        removed.push(key);
      } else if (config1[key] !== config2[key]) {
        modified.push(key);
      } else {
        unchanged.push(key);
      }
    }

    for (const key of keys2) {
      if (!(key in config1)) {
        added.push(key);
      }
    }

    return {
      differences: [...added, ...removed, ...modified],
      added,
      removed,
      modified,
      unchanged,
    };
  } catch {
    return null;
  }
}

/**
 * Parsea líneas de configuración (simplificado)
 */
function parseConfigLines(config: string): Record<string, string> {
  const lines: Record<string, string> = {};
  const configLines = config.split('\n');
  let currentSection = '';

  for (const line of configLines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('config ') || trimmed.startsWith('edit ')) {
      currentSection = trimmed;
    } else if (trimmed.startsWith('set ') || trimmed.startsWith('unset ')) {
      lines[`${currentSection}:${trimmed}`] = trimmed;
    }
  }

  return lines;
}

/**
 * Exporta un backup a formato descargable
 */
export async function exportBackup(backupId: string): Promise<{ filename: string; content: Buffer } | null> {
  try {
    const backup = await getBackup(backupId);
    if (!backup) return null;

    return {
      filename: backup.metadata.filename,
      content: Buffer.from(backup.content, 'utf8'),
    };
  } catch {
    return null;
  }
}

/**
 * Importa un backup desde archivo
 */
export async function importBackup(
  filename: string,
  content: string,
  metadata?: Partial<BackupMetadata>
): Promise<BackupResult> {
  try {
    await initializeBackupSystem();

    const backupId = generateBackupId();
    const timestamp = new Date().toISOString();
    const hash = calculateHash(content);

    const fullMetadata: BackupMetadata = {
      id: backupId,
      filename,
      createdAt: timestamp,
      hostname: metadata?.hostname || 'imported',
      serial: metadata?.serial || 'unknown',
      version: metadata?.version || 'unknown',
      vdom: metadata?.vdom || 'root',
      scope: metadata?.scope || 'global',
      size: Buffer.byteLength(content, 'utf8'),
      hash,
      description: metadata?.description || 'Imported backup',
      triggeredBy: 'import',
      autoBackup: false,
    };

    // Guardar archivo
    const backupPath = join(BACKUP_DIR, filename);
    await writeFile(backupPath, content, 'utf8');

    // Guardar metadata
    const metadataPath = join(BACKUP_DIR, `${filename}.json`);
    await writeFile(metadataPath, JSON.stringify(fullMetadata, null, 2), 'utf8');

    return {
      success: true,
      backupId,
      filename,
      metadata: fullMetadata,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error importing backup',
    };
  }
}

/**
 * Limpia backups antiguos según retención
 */
async function cleanupOldBackups(): Promise<void> {
  try {
    const backups = await listBackups();
    const now = new Date();
    const retentionMs = BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;

    for (const backup of backups) {
      const backupDate = new Date(backup.createdAt);
      const age = now.getTime() - backupDate.getTime();

      if (age > retentionMs && backup.autoBackup) {
        await deleteBackup(backup.id);
      }
    }
  } catch {
    // Ignorar errores de limpieza
  }
}

/**
 * Limita el número de backups mantenidos
 */
async function enforceBackupLimit(): Promise<void> {
  try {
    const backups = await listBackups();
    const autoBackups = backups.filter(b => b.autoBackup);

    if (autoBackups.length > MAX_BACKUPS) {
      const toDelete = autoBackups.slice(MAX_BACKUPS);
      for (const backup of toDelete) {
        await deleteBackup(backup.id);
      }
    }
  } catch {
    // Ignorar errores de limpieza
  }
}

/**
 * Obtiene estadísticas de backups
 */
export async function getBackupStats(): Promise<{
  total: number;
  auto: number;
  manual: number;
  totalSize: number;
  oldest: string | null;
  newest: string | null;
}> {
  try {
    const backups = await listBackups();
    const auto = backups.filter(b => b.autoBackup).length;
    const totalSize = backups.reduce((sum, b) => sum + b.size, 0);

    return {
      total: backups.length,
      auto,
      manual: backups.length - auto,
      totalSize,
      oldest: backups.length > 0 ? backups[backups.length - 1].createdAt : null,
      newest: backups.length > 0 ? backups[0].createdAt : null,
    };
  } catch {
    return {
      total: 0,
      auto: 0,
      manual: 0,
      totalSize: 0,
      oldest: null,
      newest: null,
    };
  }
}

// Inicializar al cargar
initializeBackupSystem().catch(() => {});

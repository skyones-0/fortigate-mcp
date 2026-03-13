/**
 * Sistema de rollback para FortiGate
 * Maneja snapshots de configuración y operaciones de rollback
 */

import { writeFile, readFile, mkdir, readdir, unlink } from 'fs/promises';
import { existsSync } from 'fs';
import { join } from 'path';
import { createHash, randomBytes } from 'crypto';
import type { FortiGateClient } from '../client/fortigate-client.js';

// Directorio de snapshots
const SNAPSHOT_DIR = process.env.FORTIGATE_SNAPSHOT_DIR || './snapshots';
const MAX_SNAPSHOTS = parseInt(process.env.FORTIGATE_MAX_SNAPSHOTS || '20');
const SNAPSHOT_RETENTION_DAYS = parseInt(process.env.FORTIGATE_SNAPSHOT_RETENTION || '7');

// Interfaz para snapshot
export interface Snapshot {
  id: string;
  name: string;
  createdAt: string;
  hostname: string;
  serial: string;
  version: string;
  vdom: string;
  scope: 'global' | 'vdom';
  config: string;
  hash: string;
  description?: string;
  triggeredBy: string;
  tags?: string[];
}

// Interfaz para cambio registrado
export interface ConfigChange {
  id: string;
  timestamp: string;
  toolName: string;
  args: Record<string, unknown>;
  snapshotBefore: string;
  snapshotAfter?: string;
  success: boolean;
  error?: string;
  vdom: string;
  user?: string;
}

// Interfaz para resultado de rollback
export interface RollbackResult {
  success: boolean;
  snapshotId?: string;
  changes?: ConfigChange[];
  error?: string;
}

// Historial de cambios en memoria (en producción usar base de datos)
const changeHistory: ConfigChange[] = [];
const MAX_HISTORY_ITEMS = 1000;

/**
 * Inicializa el directorio de snapshots
 */
export async function initializeSnapshotSystem(): Promise<void> {
  if (!existsSync(SNAPSHOT_DIR)) {
    await mkdir(SNAPSHOT_DIR, { recursive: true });
  }
}

/**
 * Genera ID único para snapshot
 */
function generateSnapshotId(): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const random = randomBytes(4).toString('hex');
  return `snapshot-${timestamp}-${random}`;
}

/**
 * Calcula hash de configuración
 */
function calculateConfigHash(config: string): string {
  return createHash('sha256').update(config).digest('hex').substring(0, 16);
}

/**
 * Crea un snapshot de la configuración actual
 */
export async function createSnapshot(
  client: FortiGateClient,
  options: {
    name?: string;
    description?: string;
    scope?: 'global' | 'vdom';
    vdom?: string;
    tags?: string[];
    triggeredBy?: string;
  } = {}
): Promise<{ success: boolean; snapshot?: Snapshot; error?: string }> {
  try {
    await initializeSnapshotSystem();

    const scope = options.scope || 'global';
    const vdom = options.vdom || 'root';

    // Obtener información del sistema
    const systemStatus = await client.getSystemStatus();
    const hostname = systemStatus.hostname || 'unknown';
    const serial = systemStatus.serial || 'unknown';
    const version = systemStatus.version || 'unknown';

    // Crear backup para el snapshot
    const config = await client.backupConfig(scope);
    const hash = calculateConfigHash(config);

    const snapshotId = generateSnapshotId();
    const timestamp = new Date().toISOString();
    const name = options.name || `snapshot-${timestamp}`;

    const snapshot: Snapshot = {
      id: snapshotId,
      name,
      createdAt: timestamp,
      hostname,
      serial,
      version,
      vdom,
      scope,
      config,
      hash,
      description: options.description,
      triggeredBy: options.triggeredBy || 'manual',
      tags: options.tags,
    };

    // Guardar snapshot
    const snapshotPath = join(SNAPSHOT_DIR, `${snapshotId}.json`);
    await writeFile(snapshotPath, JSON.stringify(snapshot, null, 2), 'utf8');

    // Limpiar snapshots antiguos
    await cleanupOldSnapshots();

    // Limitar número de snapshots
    await enforceSnapshotLimit();

    return { success: true, snapshot };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error creating snapshot',
    };
  }
}

/**
 * Lista todos los snapshots disponibles
 */
export async function listSnapshots(
  options: {
    vdom?: string;
    scope?: 'global' | 'vdom';
    tag?: string;
    limit?: number;
  } = {}
): Promise<Snapshot[]> {
  try {
    await initializeSnapshotSystem();

    const files = await readdir(SNAPSHOT_DIR);
    const snapshotFiles = files.filter(f => f.startsWith('snapshot-') && f.endsWith('.json'));

    const snapshots: Snapshot[] = [];

    for (const file of snapshotFiles) {
      try {
        const snapshotPath = join(SNAPSHOT_DIR, file);
        const content = await readFile(snapshotPath, 'utf8');
        const snapshot: Snapshot = JSON.parse(content);

        // Aplicar filtros
        if (options.vdom && snapshot.vdom !== options.vdom) continue;
        if (options.scope && snapshot.scope !== options.scope) continue;
        if (options.tag && (!snapshot.tags || !snapshot.tags.includes(options.tag))) continue;

        snapshots.push(snapshot);
      } catch {
        continue;
      }
    }

    // Ordenar por fecha descendente
    snapshots.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

    if (options.limit && options.limit > 0) {
      return snapshots.slice(0, options.limit);
    }

    return snapshots;
  } catch (error) {
    throw new Error(`Failed to list snapshots: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/**
 * Obtiene un snapshot específico
 */
export async function getSnapshot(snapshotId: string): Promise<Snapshot | null> {
  try {
    const snapshotPath = join(SNAPSHOT_DIR, `${snapshotId}.json`);
    
    if (!existsSync(snapshotPath)) {
      return null;
    }

    const content = await readFile(snapshotPath, 'utf8');
    return JSON.parse(content) as Snapshot;
  } catch {
    return null;
  }
}

/**
 * Elimina un snapshot
 */
export async function deleteSnapshot(snapshotId: string): Promise<boolean> {
  try {
    const snapshotPath = join(SNAPSHOT_DIR, `${snapshotId}.json`);
    
    if (!existsSync(snapshotPath)) {
      return false;
    }

    await unlink(snapshotPath);
    return true;
  } catch {
    return false;
  }
}

/**
 * Realiza rollback a un snapshot específico
 */
export async function rollbackToSnapshot(
  client: FortiGateClient,
  snapshotId: string,
  options: {
    createPreRollbackSnapshot?: boolean;
    description?: string;
  } = {}
): Promise<RollbackResult> {
  try {
    const snapshot = await getSnapshot(snapshotId);

    if (!snapshot) {
      return { success: false, error: 'Snapshot not found' };
    }

    // Verificar compatibilidad
    const systemStatus = await client.getSystemStatus();
    if (snapshot.serial !== systemStatus.serial) {
      return {
        success: false,
        error: `Snapshot serial ${snapshot.serial} does not match current device ${systemStatus.serial}`,
      };
    }

    // Crear snapshot antes del rollback (opcional)
    let preRollbackSnapshot: Snapshot | undefined;
    if (options.createPreRollbackSnapshot !== false) {
      const result = await createSnapshot(client, {
        name: `pre-rollback-${snapshotId}`,
        description: `Automatic snapshot before rollback to ${snapshotId}`,
        scope: snapshot.scope,
        vdom: snapshot.vdom,
        triggeredBy: 'rollback',
      });
      if (result.success && result.snapshot) {
        preRollbackSnapshot = result.snapshot;
      }
    }

    // Realizar rollback
    await client.restoreConfig(snapshot.config, snapshot.scope);

    // Registrar cambio
    const change: ConfigChange = {
      id: generateSnapshotId(),
      timestamp: new Date().toISOString(),
      toolName: 'rollback_to_snapshot',
      args: { snapshotId },
      snapshotBefore: preRollbackSnapshot?.id || '',
      snapshotAfter: snapshotId,
      success: true,
      vdom: snapshot.vdom,
    };
    addToChangeHistory(change);

    return {
      success: true,
      snapshotId,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error during rollback',
    };
  }
}

/**
 * Compara dos snapshots y genera diff
 */
export async function compareSnapshots(
  snapshotId1: string,
  snapshotId2: string
): Promise<{
  added: string[];
  removed: string[];
  modified: string[];
  summary: string;
} | null> {
  try {
    const snapshot1 = await getSnapshot(snapshotId1);
    const snapshot2 = await getSnapshot(snapshotId2);

    if (!snapshot1 || !snapshot2) {
      return null;
    }

    // Parsear configuraciones
    const config1 = parseConfig(snapshot1.config);
    const config2 = parseConfig(snapshot2.config);

    const added: string[] = [];
    const removed: string[] = [];
    const modified: string[] = [];

    // Comparar
    for (const [key, value] of Object.entries(config2)) {
      if (!(key in config1)) {
        added.push(`+ ${key}: ${value}`);
      } else if (config1[key] !== value) {
        modified.push(`~ ${key}:`);
        modified.push(`  - ${config1[key]}`);
        modified.push(`  + ${value}`);
      }
    }

    for (const key of Object.keys(config1)) {
      if (!(key in config2)) {
        removed.push(`- ${key}: ${config1[key]}`);
      }
    }

    const summary = [
      `Added: ${added.length} items`,
      `Removed: ${removed.length} items`,
      `Modified: ${modified.length / 3} items`,
    ].join(', ');

    return { added, removed, modified, summary };
  } catch {
    return null;
  }
}

/**
 * Parsea configuración en estructura clave-valor
 */
function parseConfig(config: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = config.split('\n');
  let currentPath = '';

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;

    if (trimmed.startsWith('config ')) {
      currentPath = trimmed.replace('config ', '').trim();
    } else if (trimmed.startsWith('edit ')) {
      currentPath += `/${trimmed.replace('edit ', '').trim()}`;
    } else if (trimmed.startsWith('set ')) {
      const setMatch = trimmed.match(/set\s+(\S+)\s+(.+)/);
      if (setMatch) {
        result[`${currentPath}:${setMatch[1]}`] = setMatch[2];
      }
    } else if (trimmed === 'next') {
      currentPath = currentPath.substring(0, currentPath.lastIndexOf('/'));
    } else if (trimmed === 'end') {
      currentPath = '';
    }
  }

  return result;
}

/**
 * Obtiene el historial de cambios
 */
export function getChangeHistory(
  options: {
    vdom?: string;
    toolName?: string;
    since?: string;
    limit?: number;
    successOnly?: boolean;
  } = {}
): ConfigChange[] {
  let history = [...changeHistory];

  if (options.vdom) {
    history = history.filter(c => c.vdom === options.vdom);
  }

  if (options.toolName) {
    history = history.filter(c => c.toolName === options.toolName);
  }

  if (options.since) {
    const sinceDate = new Date(options.since);
    history = history.filter(c => new Date(c.timestamp) >= sinceDate);
  }

  if (options.successOnly) {
    history = history.filter(c => c.success);
  }

  // Ordenar descendente
  history.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  if (options.limit && options.limit > 0) {
    history = history.slice(0, options.limit);
  }

  return history;
}

/**
 * Agrega entrada al historial de cambios
 */
export function addToChangeHistory(change: ConfigChange): void {
  changeHistory.unshift(change);
  
  // Limitar tamaño del historial
  if (changeHistory.length > MAX_HISTORY_ITEMS) {
    changeHistory.pop();
  }
}

/**
 * Obtiene el último snapshot antes de una fecha específica
 */
export async function getLastSnapshotBefore(
  date: Date,
  options: { vdom?: string; scope?: 'global' | 'vdom' } = {}
): Promise<Snapshot | null> {
  const snapshots = await listSnapshots(options);
  
  for (const snapshot of snapshots) {
    const snapshotDate = new Date(snapshot.createdAt);
    if (snapshotDate < date) {
      return snapshot;
    }
  }

  return null;
}

/**
 * Obtiene cambios desde un snapshot específico
 */
export async function getChangesSinceSnapshot(
  snapshotId: string
): Promise<ConfigChange[]> {
  const snapshot = await getSnapshot(snapshotId);
  if (!snapshot) return [];

  const snapshotDate = new Date(snapshot.createdAt);
  return getChangeHistory({ since: snapshotDate.toISOString() });
}

/**
 * Limpia snapshots antiguos
 */
async function cleanupOldSnapshots(): Promise<void> {
  try {
    const snapshots = await listSnapshots({});
    const now = new Date();
    const retentionMs = SNAPSHOT_RETENTION_DAYS * 24 * 60 * 60 * 1000;

    for (const snapshot of snapshots) {
      const snapshotDate = new Date(snapshot.createdAt);
      const age = now.getTime() - snapshotDate.getTime();

      if (age > retentionMs && snapshot.triggeredBy === 'auto') {
        await deleteSnapshot(snapshot.id);
      }
    }
  } catch {
    // Ignorar errores de limpieza
  }
}

/**
 * Limita el número de snapshots
 */
async function enforceSnapshotLimit(): Promise<void> {
  try {
    const snapshots = await listSnapshots();
    const autoSnapshots = snapshots.filter(s => s.triggeredBy === 'auto');

    if (autoSnapshots.length > MAX_SNAPSHOTS) {
      const toDelete = autoSnapshots.slice(MAX_SNAPSHOTS);
      for (const snapshot of toDelete) {
        await deleteSnapshot(snapshot.id);
      }
    }
  } catch {
    // Ignorar errores de limpieza
  }
}

/**
 * Obtiene preview de rollback (qué cambios se revertirían)
 */
export async function previewRollback(
  client: FortiGateClient,
  snapshotId: string
): Promise<{
  canRollback: boolean;
  currentSnapshot?: Snapshot;
  targetSnapshot: Snapshot;
  differences: string;
  warnings: string[];
} | null> {
  try {
    const targetSnapshot = await getSnapshot(snapshotId);
    if (!targetSnapshot) return null;

    // Crear snapshot actual temporal
    const currentResult = await createSnapshot(client, {
      name: 'temp-preview',
      triggeredBy: 'preview',
    });

    if (!currentResult.success || !currentResult.snapshot) {
      return null;
    }

    // Comparar
    const comparison = await compareSnapshots(
      currentResult.snapshot.id,
      snapshotId
    );

    // Eliminar snapshot temporal
    await deleteSnapshot(currentResult.snapshot.id);

    const warnings: string[] = [];

    // Verificar versiones
    const systemStatus = await client.getSystemStatus();
    if (targetSnapshot.version !== systemStatus.version) {
      warnings.push(`Version mismatch: current ${systemStatus.version}, snapshot ${targetSnapshot.version}`);
    }

    // Verificar serial
    if (targetSnapshot.serial !== systemStatus.serial) {
      warnings.push(`Serial mismatch: current ${systemStatus.serial}, snapshot ${targetSnapshot.serial}`);
    }

    return {
      canRollback: targetSnapshot.serial === systemStatus.serial,
      currentSnapshot: currentResult.snapshot,
      targetSnapshot,
      differences: comparison?.summary || 'No differences detected',
      warnings,
    };
  } catch {
    return null;
  }
}

/**
 * Descarta cambios no guardados
 * En FortiGate, esto significa revertir a la configuración guardada
 */
export async function discardChanges(
  client: FortiGateClient,
  vdom?: string
): Promise<{ success: boolean; message?: string; error?: string }> {
  try {
    // Ejecutar comando CLI para descartar cambios
    await client.executeCLICommand('abort', vdom);
    
    return {
      success: true,
      message: 'Unsaved changes have been discarded',
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Failed to discard changes',
    };
  }
}

/**
 * Obtiene estadísticas de snapshots
 */
export async function getSnapshotStats(): Promise<{
  total: number;
  byVdom: Record<string, number>;
  byScope: Record<string, number>;
  oldest: string | null;
  newest: string | null;
}> {
  try {
    const snapshots = await listSnapshots();
    
    const byVdom: Record<string, number> = {};
    const byScope: Record<string, number> = {};

    for (const snapshot of snapshots) {
      byVdom[snapshot.vdom] = (byVdom[snapshot.vdom] || 0) + 1;
      byScope[snapshot.scope] = (byScope[snapshot.scope] || 0) + 1;
    }

    return {
      total: snapshots.length,
      byVdom,
      byScope,
      oldest: snapshots.length > 0 ? snapshots[snapshots.length - 1].createdAt : null,
      newest: snapshots.length > 0 ? snapshots[0].createdAt : null,
    };
  } catch {
    return {
      total: 0,
      byVdom: {},
      byScope: {},
      oldest: null,
      newest: null,
    };
  }
}

// Inicializar al cargar
initializeSnapshotSystem().catch(() => {});

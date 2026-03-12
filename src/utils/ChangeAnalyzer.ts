/**
 * Sistema de análisis de cambios para FortiGate MCP
 * Detecta, registra y analiza cambios en la configuración
 */

import { ChangeState, FortiGateApiResponse } from '../types';
import { logger, auditLogger } from './logger';
import { v4 as uuidv4 } from 'uuid';
import { format } from 'date-fns';

export interface ChangeAnalysis {
  changeId: string;
  timestamp: Date;
  module: string;
  resource: string;
  operation: 'create' | 'update' | 'delete';
  summary: string;
  details: ChangeDetail[];
  impact: ChangeImpact;
  rollbackAvailable: boolean;
  previousState?: any;
  newState?: any;
  vdom: string;
  user?: string;
}

export interface ChangeDetail {
  field: string;
  oldValue: any;
  newValue: any;
  type: 'added' | 'modified' | 'removed';
}

export interface ChangeImpact {
  level: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  affectedResources: string[];
  potentialIssues: string[];
  recommendations: string[];
}

export class ChangeAnalyzer {
  private changes: Map<string, ChangeState> = new Map();
  private maxStoredChanges: number = 1000;

  /**
   * Registra un nuevo cambio
   */
  recordChange(
    module: string,
    resource: string,
    operation: 'create' | 'update' | 'delete',
    previousState: any,
    newState: any,
    vdom: string = 'root',
    user?: string,
    description?: string
  ): ChangeState {
    const changeId = uuidv4();
    const timestamp = new Date();

    const change: ChangeState = {
      id: changeId,
      timestamp,
      operation,
      module,
      resource,
      previousState,
      newState,
      vdom,
      user,
      description,
      rollbackAvailable: operation !== 'delete' || previousState !== undefined
    };

    // Almacenar el cambio
    this.changes.set(changeId, change);

    // Limpiar cambios antiguos si excedemos el límite
    this.cleanupOldChanges();

    // Registrar en auditoría
    auditLogger.info('Cambio registrado', {
      changeId,
      module,
      resource,
      operation,
      vdom,
      user,
      description
    });

    logger.info(`Cambio registrado: ${changeId} - ${module}/${resource} (${operation})`);

    return change;
  }

  /**
   * Analiza un cambio y genera un informe detallado
   */
  analyzeChange(changeId: string): ChangeAnalysis | null {
    const change = this.changes.get(changeId);
    if (!change) {
      logger.warn(`Cambio no encontrado: ${changeId}`);
      return null;
    }

    const details = this.extractChangeDetails(change);
    const impact = this.assessImpact(change, details);

    const analysis: ChangeAnalysis = {
      changeId: change.id,
      timestamp: change.timestamp,
      module: change.module,
      resource: change.resource,
      operation: change.operation,
      summary: this.generateSummary(change, details),
      details,
      impact,
      rollbackAvailable: change.rollbackAvailable,
      previousState: change.previousState,
      newState: change.newState,
      vdom: change.vdom,
      user: change.user
    };

    auditLogger.info('Análisis de cambio completado', {
      changeId,
      impactLevel: impact.level,
      detailCount: details.length
    });

    return analysis;
  }

  /**
   * Extrae los detalles de un cambio comparando estados
   */
  private extractChangeDetails(change: ChangeState): ChangeDetail[] {
    const details: ChangeDetail[] = [];

    if (change.operation === 'create') {
      // Para creaciones, todos los campos son nuevos
      for (const [key, value] of Object.entries(change.newState || {})) {
        if (key !== 'q_origin_key' && key !== 'uuid') {
          details.push({
            field: key,
            oldValue: undefined,
            newValue: value,
            type: 'added'
          });
        }
      }
    } else if (change.operation === 'delete') {
      // Para eliminaciones, todos los campos fueron removidos
      for (const [key, value] of Object.entries(change.previousState || {})) {
        if (key !== 'q_origin_key' && key !== 'uuid') {
          details.push({
            field: key,
            oldValue: value,
            newValue: undefined,
            type: 'removed'
          });
        }
      }
    } else if (change.operation === 'update') {
      // Para actualizaciones, comparar campo por campo
      const prev = change.previousState || {};
      const curr = change.newState || {};

      // Campos modificados o agregados
      for (const [key, value] of Object.entries(curr)) {
        if (key === 'q_origin_key' || key === 'uuid') continue;

        if (!(key in prev)) {
          details.push({
            field: key,
            oldValue: undefined,
            newValue: value,
            type: 'added'
          });
        } else if (JSON.stringify(prev[key]) !== JSON.stringify(value)) {
          details.push({
            field: key,
            oldValue: prev[key],
            newValue: value,
            type: 'modified'
          });
        }
      }

      // Campos removidos
      for (const key of Object.keys(prev)) {
        if (key === 'q_origin_key' || key === 'uuid') continue;
        if (!(key in curr)) {
          details.push({
            field: key,
            oldValue: prev[key],
            newValue: undefined,
            type: 'removed'
          });
        }
      }
    }

    return details;
  }

  /**
   * Genera un resumen del cambio
   */
  private generateSummary(change: ChangeState, details: ChangeDetail[]): string {
    const operationText = {
      create: 'Creación',
      update: 'Actualización',
      delete: 'Eliminación'
    };

    let summary = `${operationText[change.operation]} de ${change.module}/${change.resource}`;
    
    if (change.operation === 'create') {
      summary += ` con ${details.length} campos configurados`;
    } else if (change.operation === 'delete') {
      summary += ` (ID: ${change.previousState?.name || change.previousState?.policyid || 'N/A'})`;
    } else if (change.operation === 'update') {
      const modifiedCount = details.filter(d => d.type === 'modified').length;
      const addedCount = details.filter(d => d.type === 'added').length;
      const removedCount = details.filter(d => d.type === 'removed').length;
      summary += `: ${modifiedCount} modificados, ${addedCount} agregados, ${removedCount} removidos`;
    }

    return summary;
  }

  /**
   * Evalúa el impacto de un cambio
   */
  private assessImpact(change: ChangeState, details: ChangeDetail[]): ChangeImpact {
    let level: 'low' | 'medium' | 'high' | 'critical' = 'low';
    const affectedResources: string[] = [];
    const potentialIssues: string[] = [];
    const recommendations: string[] = [];

    // Evaluar según el módulo
    switch (change.module.toLowerCase()) {
      case 'firewall':
        if (change.resource === 'policy') {
          // Políticas de firewall son críticas
          level = 'high';
          affectedResources.push('Tráfico de red', 'Seguridad perimeter');
          
          if (change.operation === 'delete') {
            level = 'critical';
            potentialIssues.push('Pérdida de reglas de seguridad', 'Tráfico no filtrado');
            recommendations.push('Verificar que no haya tráfico dependiente de esta política');
          }

          // Verificar cambios en acción
          const actionChange = details.find(d => d.field === 'action');
          if (actionChange) {
            if (actionChange.newValue === 'accept' && actionChange.oldValue === 'deny') {
              level = 'critical';
              potentialIssues.push('Apertura de acceso previamente bloqueado');
            }
          }
        }
        break;

      case 'system':
        if (change.resource === 'interface') {
          level = 'high';
          affectedResources.push('Conectividad de red', 'Enrutamiento');
          potentialIssues.push('Pérdida de conectividad', 'Rutas inválidas');
          recommendations.push('Verificar conectividad después del cambio');
        } else if (change.resource === 'admin') {
          level = 'critical';
          affectedResources.push('Administración del sistema', 'Seguridad de acceso');
          potentialIssues.push('Pérdida de acceso administrativo');
        } else if (change.resource === 'ha') {
          level = 'critical';
          affectedResources.push('Alta disponibilidad', 'Failover');
          potentialIssues.push('Split-brain', 'Falla de sincronización');
        }
        break;

      case 'router':
        level = 'high';
        affectedResources.push('Enrutamiento', 'Conectividad inter-red');
        potentialIssues.push('Rutas inválidas', 'Loops de enrutamiento');
        recommendations.push('Verificar tablas de enrutamiento después del cambio');
        break;

      case 'vpn':
        level = 'medium';
        affectedResources.push('Túneles VPN', 'Conectividad remota');
        potentialIssues.push('Caída de túneles VPN', 'Usuarios desconectados');
        break;

      case 'antivirus':
      case 'webfilter':
      case 'ips':
      case 'application':
        level = 'medium';
        affectedResources.push('Seguridad UTM', 'Inspección de tráfico');
        potentialIssues.push('Reducción de protección', 'Falsos positivos/negativos');
        break;

      case 'user':
        level = 'medium';
        affectedResources.push('Autenticación', 'Autorización');
        potentialIssues.push('Usuarios bloqueados', 'Acceso no autorizado');
        break;
    }

    // Ajustar nivel según la operación
    if (change.operation === 'delete' && level !== 'critical') {
      level = level === 'low' ? 'medium' : 'high';
    }

    // Generar descripción
    const descriptions: Record<string, string> = {
      low: 'Cambio de bajo impacto, riesgo mínimo',
      medium: 'Cambio de impacto moderado, requiere monitoreo',
      high: 'Cambio de alto impacto, requiere planificación de rollback',
      critical: 'Cambio crítico, requiere aprobación y plan de contingencia'
    };

    return {
      level,
      description: descriptions[level],
      affectedResources,
      potentialIssues,
      recommendations
    };
  }

  /**
   * Compara dos estados y genera un diff
   */
  generateDiff(oldState: any, newState: any): ChangeDetail[] {
    const details: ChangeDetail[] = [];

    const compareObjects = (old: any, current: any, prefix: string = '') => {
      const allKeys = new Set([...Object.keys(old || {}), ...Object.keys(current || {})]);

      for (const key of allKeys) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        const oldVal = old?.[key];
        const newVal = current?.[key];

        if (key === 'q_origin_key' || key === 'uuid') continue;

        if (!(key in (old || {}))) {
          details.push({
            field: fullKey,
            oldValue: undefined,
            newValue: newVal,
            type: 'added'
          });
        } else if (!(key in (current || {}))) {
          details.push({
            field: fullKey,
            oldValue: oldVal,
            newValue: undefined,
            type: 'removed'
          });
        } else if (typeof oldVal === 'object' && oldVal !== null && 
                   typeof newVal === 'object' && newVal !== null) {
          compareObjects(oldVal, newVal, fullKey);
        } else if (JSON.stringify(oldVal) !== JSON.stringify(newVal)) {
          details.push({
            field: fullKey,
            oldValue: oldVal,
            newValue: newVal,
            type: 'modified'
          });
        }
      }
    };

    compareObjects(oldState, newState);
    return details;
  }

  /**
   * Obtiene un cambio por ID
   */
  getChange(changeId: string): ChangeState | undefined {
    return this.changes.get(changeId);
  }

  /**
   * Obtiene todos los cambios
   */
  getAllChanges(): ChangeState[] {
    return Array.from(this.changes.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  /**
   * Obtiene cambios por módulo
   */
  getChangesByModule(module: string): ChangeState[] {
    return this.getAllChanges().filter(c => 
      c.module.toLowerCase() === module.toLowerCase()
    );
  }

  /**
   * Obtiene cambios por recurso
   */
  getChangesByResource(resource: string): ChangeState[] {
    return this.getAllChanges().filter(c => 
      c.resource.toLowerCase() === resource.toLowerCase()
    );
  }

  /**
   * Obtiene cambios por VDOM
   */
  getChangesByVdom(vdom: string): ChangeState[] {
    return this.getAllChanges().filter(c => 
      c.vdom.toLowerCase() === vdom.toLowerCase()
    );
  }

  /**
   * Obtiene cambios por usuario
   */
  getChangesByUser(user: string): ChangeState[] {
    return this.getAllChanges().filter(c => c.user === user);
  }

  /**
   * Obtiene cambios en un rango de fechas
   */
  getChangesByDateRange(startDate: Date, endDate: Date): ChangeState[] {
    return this.getAllChanges().filter(c => 
      c.timestamp >= startDate && c.timestamp <= endDate
    );
  }

  /**
   * Obtiene cambios por operación
   */
  getChangesByOperation(operation: 'create' | 'update' | 'delete'): ChangeState[] {
    return this.getAllChanges().filter(c => c.operation === operation);
  }

  /**
   * Obtiene cambios que pueden hacer rollback
   */
  getRollbackableChanges(): ChangeState[] {
    return this.getAllChanges().filter(c => c.rollbackAvailable);
  }

  /**
   * Busca cambios por término
   */
  searchChanges(searchTerm: string): ChangeState[] {
    const term = searchTerm.toLowerCase();
    return this.getAllChanges().filter(c => 
      c.module.toLowerCase().includes(term) ||
      c.resource.toLowerCase().includes(term) ||
      c.description?.toLowerCase().includes(term) ||
      c.user?.toLowerCase().includes(term) ||
      c.vdom.toLowerCase().includes(term)
    );
  }

  /**
   * Elimina un cambio del registro
   */
  removeChange(changeId: string): boolean {
    const removed = this.changes.delete(changeId);
    if (removed) {
      logger.info(`Cambio eliminado: ${changeId}`);
    }
    return removed;
  }

  /**
   * Limpia cambios antiguos
   */
  private cleanupOldChanges(): void {
    if (this.changes.size > this.maxStoredChanges) {
      const sortedChanges = this.getAllChanges();
      const toRemove = sortedChanges.slice(this.maxStoredChanges);
      
      for (const change of toRemove) {
        this.changes.delete(change.id);
      }

      logger.info(`Limpieza de cambios antiguos: ${toRemove.length} eliminados`);
    }
  }

  /**
   * Establece el número máximo de cambios a almacenar
   */
  setMaxStoredChanges(max: number): void {
    this.maxStoredChanges = max;
    this.cleanupOldChanges();
  }

  /**
   * Limpia todos los cambios
   */
  clearAllChanges(): void {
    const count = this.changes.size;
    this.changes.clear();
    logger.info(`Todos los cambios eliminados: ${count}`);
  }

  /**
   * Exporta los cambios a formato JSON
   */
  exportToJson(): string {
    const changes = this.getAllChanges();
    return JSON.stringify(changes, null, 2);
  }

  /**
   * Genera un informe de cambios
   */
  generateReport(startDate?: Date, endDate?: Date): string {
    const changes = startDate && endDate 
      ? this.getChangesByDateRange(startDate, endDate)
      : this.getAllChanges();

    const stats = {
      total: changes.length,
      create: changes.filter(c => c.operation === 'create').length,
      update: changes.filter(c => c.operation === 'update').length,
      delete: changes.filter(c => c.operation === 'delete').length,
      byModule: {} as Record<string, number>,
      byVdom: {} as Record<string, number>
    };

    for (const change of changes) {
      stats.byModule[change.module] = (stats.byModule[change.module] || 0) + 1;
      stats.byVdom[change.vdom] = (stats.byVdom[change.vdom] || 0) + 1;
    }

    let report = '=== INFORME DE CAMBIOS FORTIGATE ===\n\n';
    report += `Período: ${startDate ? format(startDate, 'yyyy-MM-dd HH:mm:ss') : 'Inicio'} - ${endDate ? format(endDate, 'yyyy-MM-dd HH:mm:ss') : 'Ahora'}\n`;
    report += `Total de cambios: ${stats.total}\n`;
    report += `  - Creaciones: ${stats.create}\n`;
    report += `  - Actualizaciones: ${stats.update}\n`;
    report += `  - Eliminaciones: ${stats.delete}\n\n`;

    report += 'Por módulo:\n';
    for (const [module, count] of Object.entries(stats.byModule)) {
      report += `  - ${module}: ${count}\n`;
    }

    report += '\nPor VDOM:\n';
    for (const [vdom, count] of Object.entries(stats.byVdom)) {
      report += `  - ${vdom}: ${count}\n`;
    }

    report += '\n=== DETALLE DE CAMBIOS ===\n';
    for (const change of changes.slice(0, 50)) { // Limitar a 50 cambios en el informe
      const analysis = this.analyzeChange(change.id);
      if (analysis) {
        report += `\n[${format(change.timestamp, 'yyyy-MM-dd HH:mm:ss')}] ${change.module}/${change.resource}\n`;
        report += `  Operación: ${change.operation}\n`;
        report += `  Usuario: ${change.user || 'N/A'}\n`;
        report += `  VDOM: ${change.vdom}\n`;
        report += `  Impacto: ${analysis.impact.level}\n`;
        report += `  Resumen: ${analysis.summary}\n`;
      }
    }

    return report;
  }

  /**
   * Obtiene estadísticas de cambios
   */
  getStatistics(): {
    totalChanges: number;
    changesByModule: Record<string, number>;
    changesByOperation: Record<string, number>;
    changesByVdom: Record<string, number>;
    rollbackableChanges: number;
    oldestChange?: Date;
    newestChange?: Date;
  } {
    const changes = this.getAllChanges();
    
    const changesByModule: Record<string, number> = {};
    const changesByOperation: Record<string, number> = {};
    const changesByVdom: Record<string, number> = {};

    for (const change of changes) {
      changesByModule[change.module] = (changesByModule[change.module] || 0) + 1;
      changesByOperation[change.operation] = (changesByOperation[change.operation] || 0) + 1;
      changesByVdom[change.vdom] = (changesByVdom[change.vdom] || 0) + 1;
    }

    return {
      totalChanges: changes.length,
      changesByModule,
      changesByOperation,
      changesByVdom,
      rollbackableChanges: changes.filter(c => c.rollbackAvailable).length,
      oldestChange: changes[changes.length - 1]?.timestamp,
      newestChange: changes[0]?.timestamp
    };
  }
}

export default ChangeAnalyzer;

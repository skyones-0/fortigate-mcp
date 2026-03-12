/**
 * Sistema de Rollback para FortiGate MCP
 * Permite revertir cambios a estados anteriores
 */

import { ChangeState, FortiGateApiResponse } from '../types';
import { FortiGateClient } from './FortiGateClient';
import { ChangeAnalyzer } from './ChangeAnalyzer';
import { logger, rollbackLogger } from './logger';
import { v4 as uuidv4 } from 'uuid';
import { format } from 'date-fns';

export interface RollbackResult {
  success: boolean;
  rollbackId: string;
  originalChangeId: string;
  message: string;
  details?: RollbackDetail;
  error?: string;
  timestamp: Date;
}

export interface RollbackDetail {
  module: string;
  resource: string;
  operation: 'create' | 'update' | 'delete';
  previousState?: any;
  newState?: any;
  apiCalls: ApiCallDetail[];
}

export interface ApiCallDetail {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  data?: any;
  success: boolean;
  response?: any;
  error?: string;
}

export interface RollbackPlan {
  planId: string;
  originalChangeId: string;
  steps: RollbackStep[];
  estimatedTime: number;
  risk: 'low' | 'medium' | 'high';
  prerequisites: string[];
  warnings: string[];
}

export interface RollbackStep {
  stepNumber: number;
  description: string;
  action: 'create' | 'update' | 'delete';
  apiCall: {
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
    path: string;
    data?: any;
  };
  verification?: {
    type: 'exists' | 'not-exists' | 'equals';
    path: string;
    expectedValue?: any;
  };
}

export class RollbackManager {
  private client: FortiGateClient;
  private changeAnalyzer: ChangeAnalyzer;
  private rollbackHistory: Map<string, RollbackResult> = new Map();
  private maxRollbackHistory: number = 100;

  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    this.client = client;
    this.changeAnalyzer = changeAnalyzer;
  }

  /**
   * Crea un plan de rollback para un cambio
   */
  async createRollbackPlan(changeId: string): Promise<RollbackPlan | null> {
    const change = this.changeAnalyzer.getChange(changeId);
    if (!change) {
      logger.error(`Cambio no encontrado: ${changeId}`);
      return null;
    }

    if (!change.rollbackAvailable) {
      logger.error(`El cambio ${changeId} no permite rollback`);
      return null;
    }

    const planId = uuidv4();
    const steps: RollbackStep[] = [];
    const prerequisites: string[] = [];
    const warnings: string[] = [];
    let estimatedTime = 0;
    let risk: 'low' | 'medium' | 'high' = 'low';

    // Generar pasos según la operación original
    switch (change.operation) {
      case 'create':
        // Para una creación, el rollback es eliminar
        steps.push({
          stepNumber: 1,
          description: `Eliminar ${change.module}/${change.resource} creado`,
          action: 'delete',
          apiCall: {
            method: 'DELETE',
            path: `/api/v2/cmdb/${change.module}/${change.resource}/${this.getResourceIdentifier(change.newState)}`
          },
          verification: {
            type: 'not-exists',
            path: `/api/v2/cmdb/${change.module}/${change.resource}/${this.getResourceIdentifier(change.newState)}`
          }
        });
        estimatedTime = 5;
        break;

      case 'update':
        // Para una actualización, el rollback es restaurar el estado anterior
        const resourceId = this.getResourceIdentifier(change.previousState);
        
        steps.push({
          stepNumber: 1,
          description: `Restaurar configuración anterior de ${change.module}/${change.resource}`,
          action: 'update',
          apiCall: {
            method: 'PUT',
            path: `/api/v2/cmdb/${change.module}/${change.resource}/${resourceId}`,
            data: this.prepareRollbackData(change.previousState)
          },
          verification: {
            type: 'equals',
            path: `/api/v2/cmdb/${change.module}/${change.resource}/${resourceId}`,
            expectedValue: change.previousState
          }
        });
        estimatedTime = 10;
        break;

      case 'delete':
        // Para una eliminación, el rollback es recrear
        steps.push({
          stepNumber: 1,
          description: `Recrear ${change.module}/${change.resource} eliminado`,
          action: 'create',
          apiCall: {
            method: 'POST',
            path: `/api/v2/cmdb/${change.module}/${change.resource}`,
            data: this.prepareRollbackData(change.previousState)
          },
          verification: {
            type: 'exists',
            path: `/api/v2/cmdb/${change.module}/${change.resource}/${this.getResourceIdentifier(change.previousState)}`
          }
        });
        estimatedTime = 15;
        break;
    }

    // Agregar prerequisitos según el módulo
    switch (change.module.toLowerCase()) {
      case 'firewall':
        prerequisites.push('Acceso a políticas de firewall');
        if (change.resource === 'policy') {
          warnings.push('El rollback puede afectar el tráfico de red');
          risk = 'high';
        }
        break;
      case 'system':
        prerequisites.push('Permisos de administrador');
        if (change.resource === 'interface') {
          warnings.push('El rollback puede causar pérdida de conectividad');
          risk = 'high';
        } else if (change.resource === 'ha') {
          warnings.push('El rollback puede afectar la alta disponibilidad');
          risk = 'high';
        }
        break;
      case 'router':
        prerequisites.push('Acceso a configuración de enrutamiento');
        warnings.push('El rollback puede afectar el enrutamiento');
        risk = 'medium';
        break;
      case 'vpn':
        prerequisites.push('Acceso a configuración VPN');
        warnings.push('El rollback puede desconectar túneles VPN activos');
        risk = 'medium';
        break;
    }

    // Agregar paso de verificación final
    steps.push({
      stepNumber: steps.length + 1,
      description: 'Verificar estado después del rollback',
      action: 'update',
      apiCall: {
        method: 'GET',
        path: `/api/v2/cmdb/${change.module}/${change.resource}`
      }
    });

    const plan: RollbackPlan = {
      planId,
      originalChangeId: changeId,
      steps,
      estimatedTime,
      risk,
      prerequisites,
      warnings
    };

    rollbackLogger.info('Plan de rollback creado', {
      planId,
      changeId,
      stepCount: steps.length,
      risk
    });

    return plan;
  }

  /**
   * Ejecuta un rollback
   */
  async executeRollback(
    changeId: string,
    options: {
      dryRun?: boolean;
      skipVerification?: boolean;
      timeout?: number;
    } = {}
  ): Promise<RollbackResult> {
    const { dryRun = false, skipVerification = false, timeout = 300000 } = options;

    const rollbackId = uuidv4();
    const timestamp = new Date();

    rollbackLogger.info('Iniciando rollback', {
      rollbackId,
      changeId,
      dryRun,
      skipVerification
    });

    // Obtener el cambio
    const change = this.changeAnalyzer.getChange(changeId);
    if (!change) {
      const result: RollbackResult = {
        success: false,
        rollbackId,
        originalChangeId: changeId,
        message: 'Cambio no encontrado',
        error: `No se encontró el cambio con ID: ${changeId}`,
        timestamp
      };
      this.rollbackHistory.set(rollbackId, result);
      return result;
    }

    // Verificar que el rollback esté disponible
    if (!change.rollbackAvailable) {
      const result: RollbackResult = {
        success: false,
        rollbackId,
        originalChangeId: changeId,
        message: 'Rollback no disponible',
        error: 'El cambio no tiene información suficiente para rollback',
        timestamp
      };
      this.rollbackHistory.set(rollbackId, result);
      return result;
    }

    // Crear plan de rollback
    const plan = await this.createRollbackPlan(changeId);
    if (!plan) {
      const result: RollbackResult = {
        success: false,
        rollbackId,
        originalChangeId: changeId,
        message: 'No se pudo crear el plan de rollback',
        error: 'Error al generar el plan de rollback',
        timestamp
      };
      this.rollbackHistory.set(rollbackId, result);
      return result;
    }

    // Si es dry run, solo retornar el plan
    if (dryRun) {
      const result: RollbackResult = {
        success: true,
        rollbackId,
        originalChangeId: changeId,
        message: 'Dry run completado - Rollback planificado exitosamente',
        details: {
          module: change.module,
          resource: change.resource,
          operation: change.operation,
          apiCalls: plan.steps.map(s => ({
            method: s.apiCall.method,
            path: s.apiCall.path,
            data: s.apiCall.data,
            success: true
          }))
        },
        timestamp
      };
      return result;
    }

    // Ejecutar los pasos del plan
    const apiCalls: ApiCallDetail[] = [];
    let overallSuccess = true;

    try {
      for (const step of plan.steps) {
        rollbackLogger.info(`Ejecutando paso ${step.stepNumber}: ${step.description}`);

        const apiCall: ApiCallDetail = {
          method: step.apiCall.method,
          path: step.apiCall.path,
          data: step.apiCall.data,
          success: false
        };

        try {
          // Ejecutar la llamada API
          let response;
          switch (step.apiCall.method) {
            case 'GET':
              response = await this.client.get(step.apiCall.path);
              break;
            case 'POST':
              response = await this.client.post(step.apiCall.path, step.apiCall.data);
              break;
            case 'PUT':
              response = await this.client.put(step.apiCall.path, step.apiCall.data);
              break;
            case 'DELETE':
              response = await this.client.delete(step.apiCall.path);
              break;
            case 'PATCH':
              response = await this.client.patch(step.apiCall.path, step.apiCall.data);
              break;
          }

          apiCall.success = true;
          apiCall.response = response;

          // Verificar el resultado si es necesario
          if (!skipVerification && step.verification) {
            const verified = await this.verifyStep(step.verification);
            if (!verified) {
              throw new Error(`Verificación fallida para el paso ${step.stepNumber}`);
            }
          }

        } catch (error) {
          apiCall.success = false;
          apiCall.error = error instanceof Error ? error.message : 'Error desconocido';
          overallSuccess = false;

          rollbackLogger.error(`Error en paso ${step.stepNumber}`, {
            error: apiCall.error,
            path: step.apiCall.path
          });

          // Decidir si continuar o abortar según el error
          if (step.stepNumber === 1) {
            // Si falla el primer paso, abortar
            throw error;
          }
        }

        apiCalls.push(apiCall);
      }

    } catch (error) {
      overallSuccess = false;
      const errorMessage = error instanceof Error ? error.message : 'Error desconocido';

      rollbackLogger.error('Rollback fallido', {
        rollbackId,
        changeId,
        error: errorMessage
      });

      const result: RollbackResult = {
        success: false,
        rollbackId,
        originalChangeId: changeId,
        message: 'Rollback fallido',
        error: errorMessage,
        details: {
          module: change.module,
          resource: change.resource,
          operation: change.operation,
          previousState: change.previousState,
          newState: change.newState,
          apiCalls
        },
        timestamp
      };

      this.rollbackHistory.set(rollbackId, result);
      return result;
    }

    // Rollback exitoso
    const result: RollbackResult = {
      success: overallSuccess,
      rollbackId,
      originalChangeId: changeId,
      message: overallSuccess 
        ? 'Rollback completado exitosamente' 
        : 'Rollback completado con advertencias',
      details: {
        module: change.module,
        resource: change.resource,
        operation: change.operation,
        previousState: change.previousState,
        newState: change.newState,
        apiCalls
      },
      timestamp
    };

    this.rollbackHistory.set(rollbackId, result);
    this.cleanupRollbackHistory();

    rollbackLogger.info('Rollback completado', {
      rollbackId,
      changeId,
      success: overallSuccess
    });

    return result;
  }

  /**
   * Verifica un paso del rollback
   */
  private async verifyStep(verification: RollbackStep['verification']): Promise<boolean> {
    if (!verification) return true;

    try {
      const response = await this.client.get(verification.path);

      switch (verification.type) {
        case 'exists':
          return response.results && response.results.length > 0;
        case 'not-exists':
          return !response.results || response.results.length === 0;
        case 'equals':
          return JSON.stringify(response.results?.[0]) === JSON.stringify(verification.expectedValue);
        default:
          return true;
      }
    } catch (error) {
      return false;
    }
  }

  /**
   * Obtiene el identificador de un recurso
   */
  private getResourceIdentifier(state: any): string {
    if (!state) return '';
    return state.name || state.policyid || state.q_origin_key || state.uuid || '';
  }

  /**
   * Prepara los datos para rollback
   */
  private prepareRollbackData(state: any): any {
    if (!state) return {};

    // Clonar el estado para no modificar el original
    const data = { ...state };

    // Eliminar campos de solo lectura
    delete data.q_origin_key;
    delete data.uuid;
    delete data._scope;

    return data;
  }

  /**
   * Obtiene el historial de rollbacks
   */
  getRollbackHistory(): RollbackResult[] {
    return Array.from(this.rollbackHistory.values()).sort(
      (a, b) => b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  /**
   * Obtiene un rollback específico
   */
  getRollback(rollbackId: string): RollbackResult | undefined {
    return this.rollbackHistory.get(rollbackId);
  }

  /**
   * Obtiene rollbacks por cambio original
   */
  getRollbacksByChange(changeId: string): RollbackResult[] {
    return this.getRollbackHistory().filter(r => r.originalChangeId === changeId);
  }

  /**
   * Limpia el historial de rollbacks antiguos
   */
  private cleanupRollbackHistory(): void {
    if (this.rollbackHistory.size > this.maxRollbackHistory) {
      const sorted = this.getRollbackHistory();
      const toRemove = sorted.slice(this.maxRollbackHistory);
      
      for (const rollback of toRemove) {
        this.rollbackHistory.delete(rollback.rollbackId);
      }
    }
  }

  /**
   * Verifica si un cambio puede hacer rollback
   */
  canRollback(changeId: string): {
    canRollback: boolean;
    reason?: string;
    plan?: RollbackPlan;
  } {
    const change = this.changeAnalyzer.getChange(changeId);
    
    if (!change) {
      return { canRollback: false, reason: 'Cambio no encontrado' };
    }

    if (!change.rollbackAvailable) {
      return { canRollback: false, reason: 'El cambio no tiene información suficiente para rollback' };
    }

    // Crear plan para verificar viabilidad
    this.createRollbackPlan(changeId).then(plan => {
      if (!plan) {
        return { canRollback: false, reason: 'No se pudo crear el plan de rollback' };
      }

      return { canRollback: true, plan };
    });

    return { canRollback: true };
  }

  /**
   * Previsualiza un rollback sin ejecutarlo
   */
  async previewRollback(changeId: string): Promise<{
    change: ChangeState | undefined;
    plan: RollbackPlan | null;
    analysis: {
      steps: number;
      estimatedTime: number;
      risk: string;
      warnings: string[];
      prerequisites: string[];
    }
  }> {
    const change = this.changeAnalyzer.getChange(changeId);
    const plan = await this.createRollbackPlan(changeId);

    return {
      change,
      plan,
      analysis: {
        steps: plan?.steps.length || 0,
        estimatedTime: plan?.estimatedTime || 0,
        risk: plan?.risk || 'low',
        warnings: plan?.warnings || [],
        prerequisites: plan?.prerequisites || []
      }
    };
  }

  /**
   * Ejecuta rollback de múltiples cambios
   */
  async executeBatchRollback(
    changeIds: string[],
    options: {
      stopOnError?: boolean;
      dryRun?: boolean;
    } = {}
  ): Promise<RollbackResult[]> {
    const { stopOnError = true, dryRun = false } = options;
    const results: RollbackResult[] = [];

    for (const changeId of changeIds) {
      const result = await this.executeRollback(changeId, { dryRun });
      results.push(result);

      if (!result.success && stopOnError) {
        logger.warn('Batch rollback detenido debido a error', { changeId });
        break;
      }
    }

    return results;
  }

  /**
   * Genera un informe de rollback
   */
  generateReport(): string {
    const history = this.getRollbackHistory();
    
    let report = '=== INFORME DE ROLLBACKS ===\n\n';
    report += `Total de rollbacks: ${history.length}\n`;
    report += `Exitosos: ${history.filter(r => r.success).length}\n`;
    report += `Fallidos: ${history.filter(r => !r.success).length}\n\n`;

    report += '=== DETALLE DE ROLLBACKS ===\n';
    for (const rollback of history.slice(0, 20)) {
      report += `\n[${format(rollback.timestamp, 'yyyy-MM-dd HH:mm:ss')}] ${rollback.rollbackId}\n`;
      report += `  Cambio original: ${rollback.originalChangeId}\n`;
      report += `  Estado: ${rollback.success ? 'EXITOSO' : 'FALLIDO'}\n`;
      report += `  Mensaje: ${rollback.message}\n`;
      if (rollback.error) {
        report += `  Error: ${rollback.error}\n`;
      }
    }

    return report;
  }

  /**
   * Exporta el historial de rollbacks a JSON
   */
  exportToJson(): string {
    return JSON.stringify(this.getRollbackHistory(), null, 2);
  }

  /**
   * Limpia todo el historial de rollbacks
   */
  clearHistory(): void {
    this.rollbackHistory.clear();
    logger.info('Historial de rollbacks limpiado');
  }
}

export default RollbackManager;

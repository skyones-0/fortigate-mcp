/**
 * Módulo base para todos los módulos de FortiGate MCP
 */

import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { CommandValidator } from '../validators/CommandValidator';
import { FortiGateApiResponse, ValidationResult, ChangeState } from '../types';
import { logger } from '../utils/logger';

export interface ModuleConfig {
  name: string;
  apiPath: string;
  supportsCrud: boolean;
  supportsMonitoring: boolean;
}

export abstract class BaseModule {
  protected client: FortiGateClient;
  protected changeAnalyzer: ChangeAnalyzer;
  protected validator: CommandValidator;
  protected config: ModuleConfig;

  constructor(
    client: FortiGateClient,
    changeAnalyzer: ChangeAnalyzer,
    config: ModuleConfig
  ) {
    this.client = client;
    this.changeAnalyzer = changeAnalyzer;
    this.validator = new CommandValidator();
    this.config = config;
  }

  /**
   * Obtiene todos los recursos del módulo
   */
  async getAll<T>(params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const validation = this.validator.validateApiOperation('GET', this.config.apiPath, undefined, {
      module: this.config.name,
      operation: 'read'
    });

    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.client.get<T>(this.config.apiPath, params);
  }

  /**
   * Obtiene un recurso específico por ID/nombre
   */
  async getById<T>(id: string | number, params?: Record<string, any>): Promise<T | null> {
    const path = `${this.config.apiPath}/${encodeURIComponent(id)}`;
    
    const validation = this.validator.validateApiOperation('GET', path, undefined, {
      module: this.config.name,
      operation: 'read'
    });

    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    try {
      const response = await this.client.get<T>(path, params);
      return response.results?.[0] || null;
    } catch (error) {
      if (error instanceof Error && error.message.includes('404')) {
        return null;
      }
      throw error;
    }
  }

  /**
   * Crea un nuevo recurso
   */
  async create<T>(data: any, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    if (!this.config.supportsCrud) {
      throw new Error(`El módulo ${this.config.name} no soporta operaciones de creación`);
    }

    const validation = this.validator.validateApiOperation('POST', this.config.apiPath, data, {
      module: this.config.name,
      operation: 'create'
    });

    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    const response = await this.client.post<T>(this.config.apiPath, data, params);

    // Registrar el cambio
    this.changeAnalyzer.recordChange(
      this.config.name,
      this.getResourceName(),
      'create',
      undefined,
      data,
      this.client.getCurrentVdom()
    );

    logger.info(`Recurso creado en ${this.config.name}`, { data });

    return response;
  }

  /**
   * Actualiza un recurso existente
   */
  async update<T>(
    id: string | number, 
    data: any, 
    params?: Record<string, any>
  ): Promise<FortiGateApiResponse<T>> {
    if (!this.config.supportsCrud) {
      throw new Error(`El módulo ${this.config.name} no soporta operaciones de actualización`);
    }

    const path = `${this.config.apiPath}/${encodeURIComponent(id)}`;

    // Obtener estado anterior para el registro de cambios
    const previousState = await this.getById(id);

    const validation = this.validator.validateApiOperation('PUT', path, data, {
      module: this.config.name,
      operation: 'update',
      previousState
    });

    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    const response = await this.client.put<T>(path, data, params);

    // Registrar el cambio
    this.changeAnalyzer.recordChange(
      this.config.name,
      this.getResourceName(),
      'update',
      previousState,
      data,
      this.client.getCurrentVdom()
    );

    logger.info(`Recurso actualizado en ${this.config.name}`, { id, data });

    return response;
  }

  /**
   * Elimina un recurso
   */
  async delete<T>(id: string | number, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    if (!this.config.supportsCrud) {
      throw new Error(`El módulo ${this.config.name} no soporta operaciones de eliminación`);
    }

    const path = `${this.config.apiPath}/${encodeURIComponent(id)}`;

    // Obtener estado anterior para el registro de cambios
    const previousState = await this.getById(id);

    const validation = this.validator.validateApiOperation('DELETE', path, undefined, {
      module: this.config.name,
      operation: 'delete',
      previousState
    });

    if (!validation.valid) {
      throw new Error(`Validación fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    const response = await this.client.delete<T>(path, params);

    // Registrar el cambio
    this.changeAnalyzer.recordChange(
      this.config.name,
      this.getResourceName(),
      'delete',
      previousState,
      undefined,
      this.client.getCurrentVdom()
    );

    logger.info(`Recurso eliminado en ${this.config.name}`, { id });

    return response;
  }

  /**
   * Obtiene información de monitoreo
   */
  async getMonitor<T>(monitorPath: string, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    if (!this.config.supportsMonitoring) {
      throw new Error(`El módulo ${this.config.name} no soporta monitoreo`);
    }

    const path = `/api/v2/monitor/${this.config.name}/${monitorPath}`;
    return this.client.get<T>(path, params);
  }

  /**
   * Busca recursos por criterios
   */
  async search<T>(criteria: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    return this.getAll<T>(criteria);
  }

  /**
   * Verifica si existe un recurso
   */
  async exists(id: string | number): Promise<boolean> {
    const resource = await this.getById(id);
    return resource !== null;
  }

  /**
   * Clona un recurso
   */
  async clone(id: string | number, newName: string): Promise<FortiGateApiResponse<any>> {
    const source = await this.getById(id);
    if (!source) {
      throw new Error(`Recurso origen no encontrado: ${id}`);
    }

    const cloneData = {
      ...source,
      name: newName
    };

    delete cloneData.q_origin_key;
    delete cloneData.uuid;
    delete cloneData.policyid;

    return this.create(cloneData);
  }

  /**
   * Obtiene estadísticas del módulo
   */
  async getStats(): Promise<any> {
    const response = await this.getAll();
    return {
      total: response.size,
      module: this.config.name,
      path: this.config.apiPath
    };
  }

  /**
   * Exporta todos los recursos
   */
  async export(): Promise<string> {
    const response = await this.getAll();
    return JSON.stringify(response.results, null, 2);
  }

  /**
   * Importa recursos desde JSON
   */
  async import(jsonData: string): Promise<FortiGateApiResponse<any>[]> {
    const data = JSON.parse(jsonData);
    const results: FortiGateApiResponse<any>[] = [];

    if (Array.isArray(data)) {
      for (const item of data) {
        try {
          const result = await this.create(item);
          results.push(result);
        } catch (error) {
          logger.error(`Error importando recurso en ${this.config.name}`, { item, error });
        }
      }
    } else {
      const result = await this.create(data);
      results.push(result);
    }

    return results;
  }

  /**
   * Obtiene el nombre del recurso
   */
  protected getResourceName(): string {
    const parts = this.config.apiPath.split('/');
    return parts[parts.length - 1] || this.config.name;
  }

  /**
   * Obtiene la configuración del módulo
   */
  getConfig(): ModuleConfig {
    return { ...this.config };
  }

  /**
   * Obtiene el nombre del módulo
   */
  getName(): string {
    return this.config.name;
  }

  /**
   * Obtiene el path de API
   */
  getApiPath(): string {
    return this.config.apiPath;
  }
}

export default BaseModule;

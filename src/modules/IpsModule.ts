/**
 * Módulo de IPS (Intrusion Prevention System) para FortiGate MCP
 * Gestiona perfiles de IPS y configuraciones
 */

import { BaseModule } from './BaseModule';
import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { 
  IpsProfile, 
  IpsEntry,
  FortiGateApiResponse,
  ValidationResult 
} from '../types';
import { logger } from '../utils/logger';

export class IpsModule extends BaseModule {
  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    super(client, changeAnalyzer, {
      name: 'ips',
      apiPath: '/api/v2/cmdb/ips/sensor',
      supportsCrud: true,
      supportsMonitoring: true
    });
  }

  /**
   * Obtiene todos los sensores/perfiles de IPS
   */
  async getSensors(params?: Record<string, any>): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.getAll<IpsProfile>(params);
  }

  /**
   * Obtiene un sensor específico
   */
  async getSensor(name: string): Promise<IpsProfile | null> {
    return this.getById<IpsProfile>(name);
  }

  /**
   * Crea un nuevo sensor de IPS
   */
  async createSensor(sensor: IpsProfile): Promise<FortiGateApiResponse<IpsProfile>> {
    const validation = this.validateSensor(sensor);
    if (!validation.valid) {
      throw new Error(`Validación de sensor fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.create<IpsProfile>(sensor);
  }

  /**
   * Actualiza un sensor de IPS
   */
  async updateSensor(
    name: string, 
    sensor: Partial<IpsProfile>
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.update<IpsProfile>(name, sensor);
  }

  /**
   * Elimina un sensor de IPS
   */
  async deleteSensor(name: string): Promise<FortiGateApiResponse<any>> {
    return this.delete(name);
  }

  /**
   * Clona un sensor de IPS
   */
  async cloneSensor(sourceName: string, newName: string): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.clone(sourceName, newName) as Promise<FortiGateApiResponse<IpsProfile>>;
  }

  /**
   * Valida un sensor de IPS
   */
  validateSensor(sensor: IpsProfile): ValidationResult {
    return this.validator.validateSecurityProfile(sensor, 'ips');
  }

  /**
   * Agrega una entrada a un sensor de IPS
   */
  async addEntry(
    sensorName: string, 
    entry: IpsEntry
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entries = sensor.entries || [];
    entries.push(entry);

    return this.update(sensorName, { entries });
  }

  /**
   * Elimina una entrada de un sensor de IPS
   */
  async removeEntry(
    sensorName: string, 
    entryId: number
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entries = (sensor.entries || []).filter(e => e.id !== entryId);
    return this.update(sensorName, { entries });
  }

  /**
   * Actualiza una entrada específica
   */
  async updateEntry(
    sensorName: string,
    entryId: number,
    entry: Partial<IpsEntry>
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entries = (sensor.entries || []).map(e => 
      e.id === entryId ? { ...e, ...entry } : e
    );

    return this.update(sensorName, { entries });
  }

  /**
   * Obtiene las estadísticas de IPS
   */
  async getStatistics(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('statistics');
  }

  /**
   * Obtiene las intrusiones detectadas
   */
  async getDetectedIntrusions(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('intrusions', params);
  }

  /**
   * Obtiene el estado de la base de datos de IPS
   */
  async getDatabaseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('database');
  }

  /**
   * Actualiza la base de datos de IPS
   */
  async updateDatabase(): Promise<FortiGateApiResponse<any>> {
    const path = '/api/v2/monitor/system/fortiguard/ips/update';
    return this.client.post(path);
  }

  /**
   * Obtiene las firmas de IPS disponibles
   */
  async getSignatures(params?: {
    filter?: string;
    limit?: number;
    offset?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/cmdb/ips/signatures', params);
  }

  /**
   * Obtiene detalles de una firma específica
   */
  async getSignatureDetails(signatureId: number): Promise<any> {
    const response = await this.client.get(`/api/v2/cmdb/ips/signatures/${signatureId}`);
    return response.results?.[0] || null;
  }

  /**
   * Configura el modo de escaneo de botnet
   */
  async setBotnetScanning(
    sensorName: string,
    action: 'disable' | 'block' | 'monitor'
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.update(sensorName, { scan_botnet_connections: action });
  }

  /**
   * Habilita/deshabilita el log de paquetes IPS
   */
  async setPacketLogging(
    sensorName: string,
    enabled: 'enable' | 'disable',
    options?: {
      quota?: number;
      memory?: number;
      interval?: number;
    }
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const update: any = { ips_packet_log: enabled };
    
    if (enabled === 'enable' && options) {
      if (options.quota) update.ips_packet_quota = options.quota;
      if (options.memory) update.ips_packet_log_memory = options.memory;
      if (options.interval) update.ips_packet_log_interval = options.interval;
    }

    return this.update(sensorName, update);
  }

  /**
   * Configura el log extendido
   */
  async setExtendedLogging(
    sensorName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.update(sensorName, { extended_log: enabled });
  }

  /**
   * Crea una entrada de filtro por severidad
   */
  async createSeverityFilter(
    sensorName: string,
    severities: string[],
    action: 'pass' | 'block' | 'reset' | 'default' = 'default'
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entries = sensor.entries || [];
    const newId = entries.length > 0 ? Math.max(...entries.map(e => e.id)) + 1 : 1;

    const entry: IpsEntry = {
      id: newId,
      q_origin_key: newId.toString(),
      severity: severities,
      action,
      status: 'enable',
      log: 'enable'
    };

    entries.push(entry);
    return this.update(sensorName, { entries });
  }

  /**
   * Crea una entrada de filtro por protocolo
   */
  async createProtocolFilter(
    sensorName: string,
    protocols: string[],
    action: 'pass' | 'block' | 'reset' | 'default' = 'default'
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entries = sensor.entries || [];
    const newId = entries.length > 0 ? Math.max(...entries.map(e => e.id)) + 1 : 1;

    const entry: IpsEntry = {
      id: newId,
      q_origin_key: newId.toString(),
      protocol: protocols,
      action,
      status: 'enable',
      log: 'enable'
    };

    entries.push(entry);
    return this.update(sensorName, { entries });
  }

  /**
   * Configura rate limiting para una entrada
   */
  async configureRateLimit(
    sensorName: string,
    entryId: number,
    options: {
      count: number;
      duration: number;
      mode: 'periodical' | 'continuous';
      track: 'source' | 'destination' | 'source-destination';
    }
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.updateEntry(sensorName, entryId, {
      rate_count: options.count,
      rate_duration: options.duration,
      rate_mode: options.mode,
      rate_track: options.track
    });
  }

  /**
   * Configura cuarentena para una entrada
   */
  async configureQuarantine(
    sensorName: string,
    entryId: number,
    options: {
      quarantine: 'none' | 'attacker' | 'both' | 'interface';
      expiry?: number;
      log?: 'enable' | 'disable';
    }
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.updateEntry(sensorName, entryId, {
      quarantine: options.quarantine,
      quarantine_expiry: options.expiry,
      quarantine_log: options.log
    });
  }

  /**
   * Agrega IPs exentas a una entrada
   */
  async addExemptIp(
    sensorName: string,
    entryId: number,
    srcIp?: string,
    dstIp?: string
  ): Promise<FortiGateApiResponse<IpsProfile>> {
    const sensor = await this.getSensor(sensorName);
    if (!sensor) {
      throw new Error(`Sensor no encontrado: ${sensorName}`);
    }

    const entry = sensor.entries?.find(e => e.id === entryId);
    if (!entry) {
      throw new Error(`Entrada no encontrada: ${entryId}`);
    }

    const exemptIps = entry.exempt_ip || [];
    const newId = exemptIps.length > 0 ? Math.max(...exemptIps.map(e => e.id)) + 1 : 1;

    exemptIps.push({
      id: newId,
      q_origin_key: newId.toString(),
      src_ip: srcIp,
      dst_ip: dstIp
    });

    return this.updateEntry(sensorName, entryId, { exempt_ip: exemptIps });
  }

  /**
   * Obtiene sensores predefinidos
   */
  async getDefaultSensors(): Promise<FortiGateApiResponse<IpsProfile>> {
    return this.getAll({ filter: 'default==enable' });
  }

  /**
   * Crea un sensor con configuración recomendada
   */
  async createRecommendedSensor(name: string): Promise<FortiGateApiResponse<IpsProfile>> {
    const recommendedSensor: IpsProfile = {
      name,
      comment: 'Sensor IPS con configuración recomendada',
      feature_set: 'flow',
      ips_log: 'enable',
      ips_packet_log: 'enable',
      ips_packet_quota: 0,
      ips_packet_log_memory: 256,
      ips_packet_log_interval: 0,
      extended_log: 'disable',
      scan_botnet_connections: 'block',
      entries: [
        {
          id: 1,
          q_origin_key: '1',
          severity: ['critical', 'high'],
          action: 'block',
          status: 'enable',
          log: 'enable',
          log_packet: 'enable',
          log_attack_context: 'enable'
        },
        {
          id: 2,
          q_origin_key: '2',
          severity: ['medium'],
          action: 'monitor',
          status: 'enable',
          log: 'enable',
          log_packet: 'disable',
          log_attack_context: 'enable'
        },
        {
          id: 3,
          q_origin_key: '3',
          severity: ['low'],
          action: 'pass',
          status: 'enable',
          log: 'enable',
          log_packet: 'disable',
          log_attack_context: 'disable'
        }
      ]
    };

    return this.createSensor(recommendedSensor);
  }

  /**
   * Obtiene el uso de recursos del motor de IPS
   */
  async getResourceUsage(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('resource-usage');
  }

  /**
   * Obtiene el estado de las sesiones IPS
   */
  async getSessionStatus(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('sessions');
  }

  /**
   * Obtiene las anomalías detectadas
   */
  async getAnomalies(params?: {
    since?: string;
    until?: string;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('anomalies', params);
  }

  /**
   * Obtiene el estado de licencia de IPS
   */
  async getLicenseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/monitor/system/fortiguard/ips/license');
  }

  /**
   * Genera un informe de actividad de IPS
   */
  async generateReport(params?: {
    since?: string;
    until?: string;
    format?: 'json' | 'csv';
  }): Promise<string> {
    const intrusions = await this.getDetectedIntrusions(params);
    
    let report = '=== INFORME DE ACTIVIDAD IPS ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n`;
    report += `Total de intrusiones detectadas: ${intrusions.size}\n\n`;

    if (intrusions.results && intrusions.results.length > 0) {
      report += '=== INTRUSIONES ===\n';
      for (const intrusion of intrusions.results) {
        report += `\nFecha: ${intrusion.date || 'N/A'}\n`;
        report += `Firma: ${intrusion.signature || 'N/A'}\n`;
        report += `Severidad: ${intrusion.severity || 'N/A'}\n`;
        report += `Acción: ${intrusion.action || 'N/A'}\n`;
        report += `Origen: ${intrusion.srcip || 'N/A'}:${intrusion.srcport || 'N/A'}\n`;
        report += `Destino: ${intrusion.dstip || 'N/A'}:${intrusion.dstport || 'N/A'}\n`;
        report += `Protocolo: ${intrusion.protocol || 'N/A'}\n`;
      }
    }

    return report;
  }
}

export default IpsModule;

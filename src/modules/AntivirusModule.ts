/**
 * Módulo de Antivirus para FortiGate MCP
 * Gestiona perfiles de antivirus y configuraciones
 */

import { BaseModule } from './BaseModule';
import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { 
  AntivirusProfile, 
  FortiGateApiResponse,
  ValidationResult 
} from '../types';
import { logger } from '../utils/logger';

export class AntivirusModule extends BaseModule {
  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    super(client, changeAnalyzer, {
      name: 'antivirus',
      apiPath: '/api/v2/cmdb/antivirus/profile',
      supportsCrud: true,
      supportsMonitoring: true
    });
  }

  /**
   * Obtiene todos los perfiles de antivirus
   */
  async getProfiles(params?: Record<string, any>): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.getAll<AntivirusProfile>(params);
  }

  /**
   * Obtiene un perfil específico
   */
  async getProfile(name: string): Promise<AntivirusProfile | null> {
    return this.getById<AntivirusProfile>(name);
  }

  /**
   * Crea un nuevo perfil de antivirus
   */
  async createProfile(profile: AntivirusProfile): Promise<FortiGateApiResponse<AntivirusProfile>> {
    // Validar el perfil antes de crear
    const validation = this.validateProfile(profile);
    if (!validation.valid) {
      throw new Error(`Validación de perfil fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.create<AntivirusProfile>(profile);
  }

  /**
   * Actualiza un perfil de antivirus
   */
  async updateProfile(
    name: string, 
    profile: Partial<AntivirusProfile>
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update<AntivirusProfile>(name, profile);
  }

  /**
   * Elimina un perfil de antivirus
   */
  async deleteProfile(name: string): Promise<FortiGateApiResponse<any>> {
    return this.delete(name);
  }

  /**
   * Clona un perfil de antivirus
   */
  async cloneProfile(sourceName: string, newName: string): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.clone(sourceName, newName) as Promise<FortiGateApiResponse<AntivirusProfile>>;
  }

  /**
   * Valida un perfil de antivirus
   */
  validateProfile(profile: AntivirusProfile): ValidationResult {
    return this.validator.validateSecurityProfile(profile, 'antivirus');
  }

  /**
   * Obtiene las estadísticas de antivirus
   */
  async getStatistics(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('statistics');
  }

  /**
   * Obtiene el estado de la base de datos de virus
   */
  async getDatabaseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('database');
  }

  /**
   * Obtiene los logs de detección de virus
   */
  async getDetectionLogs(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('virus_detected', params);
  }

  /**
   * Actualiza la base de datos de antivirus
   */
  async updateDatabase(): Promise<FortiGateApiResponse<any>> {
    const path = '/api/v2/monitor/system/fortiguard/antivirus/update';
    return this.client.post(path);
  }

  /**
   * Obtiene el estado de cuarentena
   */
  async getQuarantineStatus(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('quarantine');
  }

  /**
   * Libera un archivo de cuarentena
   */
  async releaseFromQuarantine(fileId: string): Promise<FortiGateApiResponse<any>> {
    const path = `/api/v2/monitor/antivirus/quarantine/${fileId}/release`;
    return this.client.post(path);
  }

  /**
   * Obtiene archivos en cuarentena
   */
  async getQuarantinedFiles(params?: {
    limit?: number;
    offset?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('quarantine/files', params);
  }

  /**
   * Configura el modo de inspección de un perfil
   */
  async setInspectionMode(
    profileName: string, 
    mode: 'proxy' | 'flow'
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update(profileName, { inspection_mode: mode });
  }

  /**
   * Habilita/deshabilita FortiGuard Analytics
   */
  async setFortiguardAnalytics(
    profileName: string,
    level: 'disable' | 'suspicious' | 'everything'
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update(profileName, { ftgd_analytics: level });
  }

  /**
   * Configura opciones de escaneo HTTP
   */
  async configureHttpScan(
    profileName: string,
    options: {
      scan?: 'enable' | 'disable';
      block?: 'enable' | 'disable';
      quarantine?: 'enable' | 'disable';
    }
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    const http = {
      av_scan: options.scan,
      av_block: options.block,
      av_quarantine: options.quarantine
    };

    return this.update(profileName, { http });
  }

  /**
   * Configura opciones de escaneo FTP
   */
  async configureFtpScan(
    profileName: string,
    options: {
      scan?: 'enable' | 'disable';
      block?: 'enable' | 'disable';
      quarantine?: 'enable' | 'disable';
    }
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    const ftp = {
      av_scan: options.scan,
      av_block: options.block,
      av_quarantine: options.quarantine
    };

    return this.update(profileName, { ftp });
  }

  /**
   * Configura opciones de escaneo de email
   */
  async configureEmailScan(
    profileName: string,
    protocol: 'imap' | 'pop3' | 'smtp',
    options: {
      scan?: 'enable' | 'disable';
      block?: 'enable' | 'disable';
      quarantine?: 'enable' | 'disable';
    }
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    const config = {
      av_scan: options.scan,
      av_block: options.block,
      av_quarantine: options.quarantine
    };

    return this.update(profileName, { [protocol]: config });
  }

  /**
   * Habilita/deshabilita el escaneo de archivos grandes
   */
  async setOversizeFileHandling(
    profileName: string,
    action: 'block' | 'log' | 'ignore'
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update(profileName, { oversized_file_action: action });
  }

  /**
   * Configura el escaneo con FortiSandbox
   */
  async configureSandbox(
    profileName: string,
    options: {
      analytics_db?: 'enable' | 'disable';
      analytics_bl?: 'enable' | 'disable';
      analytics_wl?: 'enable' | 'disable';
      analytics_max_upload?: number;
    }
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update(profileName, {
      analytics_db: options.analytics_db,
      analytics_bl: options.analytics_bl,
      analytics_wl: options.analytics_wl,
      analytics_max_upload: options.analytics_max_upload
    });
  }

  /**
   * Habilita/deshabilita listas de bloqueo externas
   */
  async setExternalBlocklist(
    profileName: string,
    enabled: 'enable' | 'disable',
    threatTags?: string[]
  ): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.update(profileName, {
      external_blocklist: enabled,
      external_blocklist_threat_tags: threatTags
    });
  }

  /**
   * Obtiene perfiles de antivirus predefinidos
   */
  async getDefaultProfiles(): Promise<FortiGateApiResponse<AntivirusProfile>> {
    return this.getAll({ filter: 'default==enable' });
  }

  /**
   * Crea un perfil de antivirus con configuración recomendada
   */
  async createRecommendedProfile(name: string): Promise<FortiGateApiResponse<AntivirusProfile>> {
    const recommendedProfile: AntivirusProfile = {
      name,
      inspection_mode: 'flow',
      ftgd_analytics: 'suspicious',
      av_block_log: 'enable',
      av_virus_log: 'enable',
      av_quarantine: 'enable',
      av_quarantine_expiry: 0,
      av_quarantine_log: 'enable',
      http: {
        av_scan: 'enable',
        av_block: 'enable',
        av_quarantine: 'enable',
        av_archive_log: 'enable',
        options: 'scan avmonitor block-quarantine log-all'
      },
      ftp: {
        av_scan: 'enable',
        av_block: 'enable',
        av_quarantine: 'enable',
        av_archive_log: 'enable',
        options: 'scan avmonitor block-quarantine log-all'
      },
      imap: {
        av_scan: 'enable',
        av_block: 'enable',
        av_quarantine: 'enable',
        av_archive_log: 'enable',
        options: 'scan avmonitor block-quarantine log-all'
      },
      pop3: {
        av_scan: 'enable',
        av_block: 'enable',
        av_quarantine: 'enable',
        av_archive_log: 'enable',
        options: 'scan avmonitor block-quarantine log-all'
      },
      smtp: {
        av_scan: 'enable',
        av_block: 'enable',
        av_quarantine: 'enable',
        av_archive_log: 'enable',
        options: 'scan avmonitor block-quarantine log-all'
      },
      scan_mode: 'quick',
      external_blocklist: 'enable',
      analytics_db: 'enable',
      analytics_bl: 'enable',
      analytics_wl: 'enable',
      analytics_max_upload: 10
    };

    return this.createProfile(recommendedProfile);
  }

  /**
   * Obtiene el uso de recursos del motor de antivirus
   */
  async getResourceUsage(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('resource-usage');
  }

  /**
   * Realiza un escaneo bajo demanda
   */
  async runOnDemandScan(filePath: string): Promise<FortiGateApiResponse<any>> {
    const path = '/api/v2/monitor/antivirus/ondemand';
    return this.client.post(path, { file_path: filePath });
  }

  /**
   * Obtiene la configuración de excepciones de escaneo
   */
  async getScanExceptions(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/cmdb/antivirus/exemption');
  }

  /**
   * Agrega una excepción de escaneo
   */
  async addScanException(exception: {
    id?: number;
    pattern?: string;
    type?: 'file-pattern' | 'file-type' | 'malware';
    comment?: string;
  }): Promise<FortiGateApiResponse<any>> {
    return this.client.post('/api/v2/cmdb/antivirus/exemption', exception);
  }

  /**
   * Elimina una excepción de escaneo
   */
  async removeScanException(id: number): Promise<FortiGateApiResponse<any>> {
    return this.client.delete(`/api/v2/cmdb/antivirus/exemption/${id}`);
  }

  /**
   * Obtiene el estado de licencia de antivirus
   */
  async getLicenseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/monitor/system/fortiguard/antivirus/license');
  }

  /**
   * Genera un informe de actividad de antivirus
   */
  async generateReport(params?: {
    since?: string;
    until?: string;
    format?: 'json' | 'csv';
  }): Promise<string> {
    const logs = await this.getDetectionLogs(params);
    
    let report = '=== INFORME DE ACTIVIDAD ANTIVIRUS ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n`;
    report += `Total de detecciones: ${logs.size}\n\n`;

    if (logs.results && logs.results.length > 0) {
      report += '=== DETECCIONES ===\n';
      for (const detection of logs.results) {
        report += `\nFecha: ${detection.date || 'N/A'}\n`;
        report += `Archivo: ${detection.filename || 'N/A'}\n`;
        report += `Virus: ${detection.virus || 'N/A'}\n`;
        report += `Acción: ${detection.action || 'N/A'}\n`;
        report += `Origen: ${detection.srcip || 'N/A'} -> ${detection.dstip || 'N/A'}\n`;
      }
    }

    return report;
  }
}

export default AntivirusModule;

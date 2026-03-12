/**
 * Módulo de CASB (Cloud Access Security Broker) para FortiGate MCP V7.6
 * Gestiona perfiles de CASB inline para control de aplicaciones SaaS
 */

import { BaseModule } from './BaseModule';
import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { 
  InlineCasbProfile, 
  CasbSaasApplication,
  CasbCustomControl,
  FortiGateApiResponse,
  ValidationResult 
} from '../types';
import { logger } from '../utils/logger';

export class CasbModule extends BaseModule {
  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    super(client, changeAnalyzer, {
      name: 'casb',
      apiPath: '/api/v2/cmdb/casb/profile',
      supportsCrud: true,
      supportsMonitoring: true
    });
  }

  /**
   * Obtiene todos los perfiles de CASB
   */
  async getProfiles(params?: Record<string, any>): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    return this.getAll<InlineCasbProfile>(params);
  }

  /**
   * Obtiene un perfil específico
   */
  async getProfile(name: string): Promise<InlineCasbProfile | null> {
    return this.getById<InlineCasbProfile>(name);
  }

  /**
   * Crea un nuevo perfil de CASB
   */
  async createProfile(profile: InlineCasbProfile): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const validation = this.validateProfile(profile);
    if (!validation.valid) {
      throw new Error(`Validación de perfil fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.create<InlineCasbProfile>(profile);
  }

  /**
   * Actualiza un perfil de CASB
   */
  async updateProfile(
    name: string, 
    profile: Partial<InlineCasbProfile>
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    return this.update<InlineCasbProfile>(name, profile);
  }

  /**
   * Elimina un perfil de CASB
   */
  async deleteProfile(name: string): Promise<FortiGateApiResponse<any>> {
    return this.delete(name);
  }

  /**
   * Valida un perfil de CASB
   */
  validateProfile(profile: InlineCasbProfile): ValidationResult {
    const errors: any[] = [];
    const warnings: any[] = [];

    if (!profile.name) {
      errors.push({
        field: 'name',
        message: 'El nombre del perfil es requerido',
        code: 'CASB_NAME_REQUIRED'
      });
    }

    if (profile.saas_application) {
      for (const app of profile.saas_application) {
        if (!app.name) {
          errors.push({
            field: 'saas_application.name',
            message: 'El nombre de la aplicación SaaS es requerido',
            code: 'SAAS_NAME_REQUIRED'
          });
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Agrega una aplicación SaaS a un perfil
   */
  async addSaasApplication(
    profileName: string,
    application: CasbSaasApplication
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const apps = profile.saas_application || [];
    apps.push(application);

    return this.update(profileName, { saas_application: apps });
  }

  /**
   * Actualiza una aplicación SaaS
   */
  async updateSaasApplication(
    profileName: string,
    appName: string,
    application: Partial<CasbSaasApplication>
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const apps = (profile.saas_application || []).map(app => 
      app.name === appName ? { ...app, ...application } : app
    );

    return this.update(profileName, { saas_application: apps });
  }

  /**
   * Elimina una aplicación SaaS
   */
  async removeSaasApplication(
    profileName: string,
    appName: string
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const apps = (profile.saas_application || []).filter(app => app.name !== appName);
    return this.update(profileName, { saas_application: apps });
  }

  /**
   * Agrega un control personalizado a una aplicación
   */
  async addCustomControl(
    profileName: string,
    appName: string,
    control: CasbCustomControl
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const app = profile.saas_application?.find(a => a.name === appName);
    if (!app) {
      throw new Error(`Aplicación no encontrada: ${appName}`);
    }

    const controls = app.custom_control || [];
    controls.push(control);

    const updatedApps = profile.saas_application?.map(a => 
      a.name === appName ? { ...a, custom_control: controls } : a
    );

    return this.update(profileName, { saas_application: updatedApps });
  }

  /**
   * Configura el control de privilegios para una aplicación
   */
  async configurePrivilegeControl(
    profileName: string,
    appName: string,
    options: {
      defaultAction?: 'allow' | 'block' | 'log-only';
      log?: 'enable' | 'disable';
      safeSearch?: 'enable' | 'disable';
    }
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    return this.updateSaasApplication(profileName, appName, {
      default_action: options.defaultAction,
      log: options.log,
      safe_search: options.safeSearch
    });
  }

  /**
   * Configura control de tenant
   */
  async configureTenantControl(
    profileName: string,
    appName: string,
    tenants: string[],
    action: 'allow' | 'block' | 'log-only'
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const app = profile.saas_application?.find(a => a.name === appName);
    if (!app) {
      throw new Error(`Aplicación no encontrada: ${appName}`);
    }

    // Crear controles personalizados para cada tenant
    const controls: CasbCustomControl[] = tenants.map((tenant, index) => ({
      name: `tenant_control_${index}`,
      q_origin_key: `tenant_control_${index}`,
      match: [{
        id: 1,
        q_origin_key: '1',
        tenant_extraction: 'enable',
        tenant_extraction_key: 'domain',
        tenant: [{
          name: tenant,
          q_origin_key: tenant,
          attribute_name: 'domain',
          attribute_match_pattern: 'exact',
          attribute_value: tenant,
          action
        }]
      }],
      action,
      status: 'enable'
    }));

    const updatedApps = profile.saas_application?.map(a => 
      a.name === appName ? { ...a, custom_control: controls } : a
    );

    return this.update(profileName, { saas_application: updatedApps });
  }

  /**
   * Configura bypass de UTM para actividades específicas
   */
  async configureUtmBypass(
    profileName: string,
    appName: string,
    bypassProfiles: string[]
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const app = profile.saas_application?.find(a => a.name === appName);
    if (!app) {
      throw new Error(`Aplicación no encontrada: ${appName}`);
    }

    const updatedApps = profile.saas_application?.map(a => 
      a.name === appName ? { 
        ...a, 
        control_options: {
          ...a.control_options,
          utm_bypass: bypassProfiles
        }
      } : a
    );

    return this.update(profileName, { saas_application: updatedApps });
  }

  /**
   * Obtiene las aplicaciones SaaS soportadas
   */
  async getSupportedApplications(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/cmdb/casb/saas-application');
  }

  /**
   * Obtiene los controles disponibles para una aplicación
   */
  async getApplicationControls(appName: string): Promise<any> {
    const response = await this.client.get(`/api/v2/cmdb/casb/saas-application/${appName}`);
    return response.results?.[0]?.controls || [];
  }

  /**
   * Obtiene las estadísticas de CASB
   */
  async getStatistics(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('statistics');
  }

  /**
   * Obtiene los eventos de CASB
   */
  async getEvents(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('events', params);
  }

  /**
   * Obtiene las sesiones de CASB activas
   */
  async getActiveSessions(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('sessions');
  }

  /**
   * Obtiene el uso de aplicaciones SaaS
   */
  async getSaasUsage(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('saas-usage', params);
  }

  /**
   * Obtiene las violaciones de políticas
   */
  async getPolicyViolations(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('violations', params);
  }

  /**
   * Crea un perfil CASB para Microsoft 365
   */
  async createMicrosoft365Profile(
    name: string,
    options: {
      blockUpload?: boolean;
      blockDownload?: boolean;
      blockShare?: boolean;
      allowedTenants?: string[];
    } = {}
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const { blockUpload = false, blockDownload = false, blockShare = false, allowedTenants = [] } = options;

    const controls: CasbCustomControl[] = [];
    
    if (blockUpload) {
      controls.push({
        name: 'block_upload',
        q_origin_key: 'block_upload',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    if (blockDownload) {
      controls.push({
        name: 'block_download',
        q_origin_key: 'block_download',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    if (blockShare) {
      controls.push({
        name: 'block_share',
        q_origin_key: 'block_share',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    const profile: InlineCasbProfile = {
      name,
      comment: 'Perfil CASB para Microsoft 365',
      saas_application: [
        {
          name: 'ms-teams',
          q_origin_key: 'ms-teams',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        },
        {
          name: 'ms-onedrive',
          q_origin_key: 'ms-onedrive',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        },
        {
          name: 'ms-outlook',
          q_origin_key: 'ms-outlook',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        },
        {
          name: 'sharepoint',
          q_origin_key: 'sharepoint',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        }
      ]
    };

    // Agregar controles de tenant si se especificaron
    if (allowedTenants.length > 0) {
      for (const app of profile.saas_application || []) {
        app.custom_control = app.custom_control || [];
        app.custom_control.push({
          name: 'tenant_control',
          q_origin_key: 'tenant_control',
          match: [{
            id: 1,
            q_origin_key: '1',
            tenant_extraction: 'enable',
            tenant_extraction_key: 'domain',
            tenant: allowedTenants.map(t => ({
              name: t,
              q_origin_key: t,
              attribute_name: 'domain',
              attribute_match_pattern: 'exact',
              attribute_value: t,
              action: 'allow'
            }))
          }],
          action: 'block',
          status: 'enable'
        });
      }
    }

    return this.createProfile(profile);
  }

  /**
   * Crea un perfil CASB para Google Workspace
   */
  async createGoogleWorkspaceProfile(
    name: string,
    options: {
      blockUpload?: boolean;
      blockDownload?: boolean;
      allowedDomains?: string[];
    } = {}
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const { blockUpload = false, blockDownload = false, allowedDomains = [] } = options;

    const controls: CasbCustomControl[] = [];
    
    if (blockUpload) {
      controls.push({
        name: 'block_upload',
        q_origin_key: 'block_upload',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    if (blockDownload) {
      controls.push({
        name: 'block_download',
        q_origin_key: 'block_download',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    const profile: InlineCasbProfile = {
      name,
      comment: 'Perfil CASB para Google Workspace',
      saas_application: [
        {
          name: 'gmail',
          q_origin_key: 'gmail',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        },
        {
          name: 'google-drive',
          q_origin_key: 'google-drive',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        },
        {
          name: 'google-office',
          q_origin_key: 'google-office',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        }
      ]
    };

    // Agregar controles de dominio si se especificaron
    if (allowedDomains.length > 0) {
      for (const app of profile.saas_application || []) {
        app.custom_control = app.custom_control || [];
        app.custom_control.push({
          name: 'domain_control',
          q_origin_key: 'domain_control',
          match: [{
            id: 1,
            q_origin_key: '1',
            tenant_extraction: 'enable',
            tenant_extraction_key: 'domain',
            tenant: allowedDomains.map(d => ({
              name: d,
              q_origin_key: d,
              attribute_name: 'domain',
              attribute_match_pattern: 'exact',
              attribute_value: d,
              action: 'allow'
            }))
          }],
          action: 'block',
          status: 'enable'
        });
      }
    }

    return this.createProfile(profile);
  }

  /**
   * Crea un perfil CASB para Salesforce
   */
  async createSalesforceProfile(
    name: string,
    options: {
      blockExport?: boolean;
      blockImport?: boolean;
      allowedOrgs?: string[];
    } = {}
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    const { blockExport = false, blockImport = false, allowedOrgs = [] } = options;

    const controls: CasbCustomControl[] = [];
    
    if (blockExport) {
      controls.push({
        name: 'block_export',
        q_origin_key: 'block_export',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    if (blockImport) {
      controls.push({
        name: 'block_import',
        q_origin_key: 'block_import',
        action: 'block',
        status: 'enable',
        log: 'enable'
      });
    }

    const profile: InlineCasbProfile = {
      name,
      comment: 'Perfil CASB para Salesforce',
      saas_application: [
        {
          name: 'salesforce',
          q_origin_key: 'salesforce',
          status: 'enable',
          default_action: 'allow',
          log: 'enable',
          custom_control: controls
        }
      ]
    };

    // Agregar controles de organización si se especificaron
    if (allowedOrgs.length > 0) {
      for (const app of profile.saas_application || []) {
        app.custom_control = app.custom_control || [];
        app.custom_control.push({
          name: 'org_control',
          q_origin_key: 'org_control',
          match: [{
            id: 1,
            q_origin_key: '1',
            tenant_extraction: 'enable',
            tenant_extraction_key: 'organization',
            tenant: allowedOrgs.map(o => ({
              name: o,
              q_origin_key: o,
              attribute_name: 'organization',
              attribute_match_pattern: 'exact',
              attribute_value: o,
              action: 'allow'
            }))
          }],
          action: 'block',
          status: 'enable'
        });
      }
    }

    return this.createProfile(profile);
  }

  /**
   * Obtiene perfiles predefinidos
   */
  async getDefaultProfiles(): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    return this.getAll({ filter: 'default==enable' });
  }

  /**
   * Genera un informe de actividad de CASB
   */
  async generateReport(params?: {
    since?: string;
    until?: string;
    format?: 'json' | 'csv';
  }): Promise<string> {
    const events = await this.getEvents(params);
    const violations = await this.getPolicyViolations(params);
    const usage = await this.getSaasUsage(params);
    
    let report = '=== INFORME DE ACTIVIDAD CASB ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n`;
    report += `Eventos: ${events.size}\n`;
    report += `Violaciones: ${violations.size}\n\n`;

    if (usage.results && usage.results.length > 0) {
      report += '=== USO DE APLICACIONES SAAS ===\n';
      for (const app of usage.results) {
        report += `${app.name || 'N/A'}: ${app.sessions || 0} sesiones, ${app.bytes || 0} bytes\n`;
      }
    }

    if (violations.results && violations.results.length > 0) {
      report += '\n=== VIOLACIONES DE POLÍTICAS ===\n';
      for (const v of violations.results) {
        report += `Fecha: ${v.date || 'N/A'}\n`;
        report += `Usuario: ${v.user || 'N/A'}\n`;
        report += `Aplicación: ${v.application || 'N/A'}\n`;
        report += `Violación: ${v.violation || 'N/A'}\n`;
        report += `Acción: ${v.action || 'N/A'}\n\n`;
      }
    }

    return report;
  }

  /**
   * Obtiene el estado de licencia de CASB
   */
  async getLicenseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/monitor/system/fortiguard/casb/license');
  }

  /**
   * Habilita/deshabilita el log extendido
   */
  async setExtendedLogging(
    profileName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<InlineCasbProfile>> {
    return this.update(profileName, { extended_log: enabled });
  }
}

export default CasbModule;

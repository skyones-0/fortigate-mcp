/**
 * Módulo de Web Filter para FortiGate MCP
 * Gestiona perfiles de filtrado web y configuraciones
 */

import { BaseModule } from './BaseModule';
import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { 
  WebFilterProfile, 
  FtgdFilter,
  FtgdLocalCategory,
  FtgdLocalRating,
  FortiGateApiResponse,
  ValidationResult 
} from '../types';
import { logger } from '../utils/logger';

export class WebFilterModule extends BaseModule {
  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    super(client, changeAnalyzer, {
      name: 'webfilter',
      apiPath: '/api/v2/cmdb/webfilter/profile',
      supportsCrud: true,
      supportsMonitoring: true
    });
  }

  /**
   * Obtiene todos los perfiles de filtrado web
   */
  async getProfiles(params?: Record<string, any>): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.getAll<WebFilterProfile>(params);
  }

  /**
   * Obtiene un perfil específico
   */
  async getProfile(name: string): Promise<WebFilterProfile | null> {
    return this.getById<WebFilterProfile>(name);
  }

  /**
   * Crea un nuevo perfil de filtrado web
   */
  async createProfile(profile: WebFilterProfile): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const validation = this.validateProfile(profile);
    if (!validation.valid) {
      throw new Error(`Validación de perfil fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.create<WebFilterProfile>(profile);
  }

  /**
   * Actualiza un perfil de filtrado web
   */
  async updateProfile(
    name: string, 
    profile: Partial<WebFilterProfile>
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update<WebFilterProfile>(name, profile);
  }

  /**
   * Elimina un perfil de filtrado web
   */
  async deleteProfile(name: string): Promise<FortiGateApiResponse<any>> {
    return this.delete(name);
  }

  /**
   * Valida un perfil de filtrado web
   */
  validateProfile(profile: WebFilterProfile): ValidationResult {
    return this.validator.validateSecurityProfile(profile, 'webfilter');
  }

  /**
   * Agrega un filtro de categoría FortiGuard
   */
  async addFortiguardFilter(
    profileName: string,
    filter: FtgdFilter
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const ftgdWf = profile.ftgd_wf || { filters: [] };
    const filters = ftgdWf.filters || [];
    
    // Asignar ID si no tiene
    if (filter.id === undefined) {
      filter.id = filters.length > 0 ? Math.max(...filters.map(f => f.id)) + 1 : 1;
    }

    filters.push(filter);
    ftgdWf.filters = filters;

    return this.update(profileName, { ftgd_wf: ftgdWf });
  }

  /**
   * Actualiza un filtro de categoría
   */
  async updateFortiguardFilter(
    profileName: string,
    filterId: number,
    filter: Partial<FtgdFilter>
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const ftgdWf = profile.ftgd_wf || { filters: [] };
    const filters = (ftgdWf.filters || []).map(f => 
      f.id === filterId ? { ...f, ...filter } : f
    );

    ftgdWf.filters = filters;
    return this.update(profileName, { ftgd_wf: ftgdWf });
  }

  /**
   * Elimina un filtro de categoría
   */
  async removeFortiguardFilter(
    profileName: string,
    filterId: number
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const ftgdWf = profile.ftgd_wf || { filters: [] };
    const filters = (ftgdWf.filters || []).filter(f => f.id !== filterId);

    ftgdWf.filters = filters;
    return this.update(profileName, { ftgd_wf: ftgdWf });
  }

  /**
   * Agrega una categoría local
   */
  async addLocalCategory(
    profileName: string,
    category: FtgdLocalCategory
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const categories = profile.ftgd_local_categories || [];
    categories.push(category);

    return this.update(profileName, { ftgd_local_categories: categories });
  }

  /**
   * Agrega una calificación local de URL
   */
  async addLocalRating(
    profileName: string,
    rating: FtgdLocalRating
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const ratings = profile.ftgd_local_rating || [];
    ratings.push(rating);

    return this.update(profileName, { ftgd_local_rating: ratings });
  }

  /**
   * Configura el modo de inspección
   */
  async setInspectionMode(
    profileName: string,
    mode: 'proxy' | 'flow'
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update(profileName, { inspection_mode: mode });
  }

  /**
   * Habilita/deshabilita el log de contenido web
   */
  async setContentLogging(
    profileName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update(profileName, { web_content_log: enabled });
  }

  /**
   * Habilita/deshabilita el log de filtrado web
   */
  async setFilterLogging(
    profileName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update(profileName, { web_filter_log: enabled });
  }

  /**
   * Habilita/deshabilita el log de URLs
   */
  async setUrlLogging(
    profileName: string,
    enabled: 'enable' | 'disable',
    logAll: 'enable' | 'disable' = 'disable'
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update(profileName, { 
      web_url_log: enabled,
      log_all_url: logAll
    });
  }

  /**
   * Configura opciones de HTTPS
   */
  async configureHttps(
    profileName: string,
    options: {
      replacemsg?: 'enable' | 'disable';
      ovrdPerm?: string;
    }
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.update(profileName, {
      https_replacemsg: options.replacemsg,
      ovrd_perm: options.ovrdPerm
    });
  }

  /**
   * Obtiene las estadísticas de filtrado web
   */
  async getStatistics(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('statistics');
  }

  /**
   * Obtiene las URLs bloqueadas
   */
  async getBlockedUrls(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('blocked-urls', params);
  }

  /**
   * Obtiene las URLs permitidas
   */
  async getAllowedUrls(params?: {
    since?: string;
    until?: string;
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('allowed-urls', params);
  }

  /**
   * Obtiene las categorías más visitadas
   */
  async getTopCategories(limit: number = 10): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('top-categories', { limit });
  }

  /**
   * Obtiene las URLs más visitadas
   */
  async getTopUrls(limit: number = 10): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('top-urls', { limit });
  }

  /**
   * Obtiene el estado de la base de datos de FortiGuard
   */
  async getFortiguardStatus(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/monitor/system/fortiguard/webfilter');
  }

  /**
   * Actualiza la base de datos de filtrado web
   */
  async updateDatabase(): Promise<FortiGateApiResponse<any>> {
    const path = '/api/v2/monitor/system/fortiguard/webfilter/update';
    return this.client.post(path);
  }

  /**
   * Obtiene las categorías de FortiGuard disponibles
   */
  async getFortiguardCategories(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/cmdb/webfilter/ftgd-local-cat');
  }

  /**
   * Crea un perfil con configuración recomendada
   */
  async createRecommendedProfile(name: string): Promise<FortiGateApiResponse<WebFilterProfile>> {
    const recommendedProfile: WebFilterProfile = {
      name,
      comment: 'Perfil de filtrado web recomendado',
      inspection_mode: 'flow',
      https_replacemsg: 'enable',
      ovrd_perm: 'authenticated',
      post_action: 'normal',
      web_content_log: 'enable',
      web_filter_log: 'enable',
      web_url_log: 'enable',
      web_invalid_domain_log: 'enable',
      web_ftgd_err_log: 'enable',
      web_ftgd_quota_usage: 'enable',
      extended_log: 'disable',
      web_filter_cookie: 'enable',
      web_filter_cookie_removal: 'disable',
      log_all_url: 'disable',
      ftgd_wf: {
        options: 'rate-server-ip rate-iframe rate-images rate-css-urls',
        exempt_quota: '',
        max_quota_timeout: 300,
        rate_crl_urls: 'enable',
        rate_css_urls: 'enable',
        rate_image_urls: 'enable',
        rate_javascript_urls: 'enable',
        filters: [
          {
            id: 1,
            category: 26, // Adult Material
            action: 'block',
            log: 'enable'
          },
          {
            id: 2,
            category: 61, // Malicious Websites
            action: 'block',
            log: 'enable'
          },
          {
            id: 3,
            category: 86, // Phishing
            action: 'block',
            log: 'enable'
          },
          {
            id: 4,
            category: 88, // Spam
            action: 'block',
            log: 'enable'
          }
        ]
      }
    };

    return this.createProfile(recommendedProfile);
  }

  /**
   * Obtiene perfiles predefinidos
   */
  async getDefaultProfiles(): Promise<FortiGateApiResponse<WebFilterProfile>> {
    return this.getAll({ filter: 'default==enable' });
  }

  /**
   * Configura Safe Search
   */
  async configureSafeSearch(
    profileName: string,
    enabled: boolean
  ): Promise<FortiGateApiResponse<WebFilterProfile>> {
    // Safe Search se configura en el perfil de DNS Filter
    // Este método es un placeholder para integración
    logger.info(`Configurando Safe Search para ${profileName}: ${enabled}`);
    return this.getProfile(profileName) as Promise<FortiGateApiResponse<WebFilterProfile>>;
  }

  /**
   * Agrega una URL a la lista blanca/negra local
   */
  async addUrlFilter(
    profileName: string,
    url: string,
    action: 'allow' | 'block' | 'monitor',
    type: 'url-filter' | 'fortiguard-filter' = 'url-filter'
  ): Promise<FortiGateApiResponse<any>> {
    const path = `/api/v2/cmdb/webfilter/${type}`;
    return this.client.post(path, {
      name: profileName,
      url,
      action,
      status: 'enable'
    });
  }

  /**
   * Obtiene el uso de recursos del motor de filtrado web
   */
  async getResourceUsage(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('resource-usage');
  }

  /**
   * Obtiene el estado de licencia de filtrado web
   */
  async getLicenseStatus(): Promise<FortiGateApiResponse<any>> {
    return this.client.get('/api/v2/monitor/system/fortiguard/webfilter/license');
  }

  /**
   * Genera un informe de actividad de filtrado web
   */
  async generateReport(params?: {
    since?: string;
    until?: string;
    format?: 'json' | 'csv';
  }): Promise<string> {
    const blocked = await this.getBlockedUrls(params);
    const topCategories = await this.getTopCategories(10);
    const topUrls = await this.getTopUrls(10);
    
    let report = '=== INFORME DE ACTIVIDAD WEB FILTER ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n`;
    report += `URLs bloqueadas: ${blocked.size}\n\n`;

    if (topCategories.results && topCategories.results.length > 0) {
      report += '=== CATEGORÍAS MÁS VISITADAS ===\n';
      for (const cat of topCategories.results) {
        report += `${cat.name || 'N/A'}: ${cat.hits || 0} visitas\n`;
      }
    }

    if (topUrls.results && topUrls.results.length > 0) {
      report += '\n=== URLS MÁS VISITADAS ===\n';
      for (const url of topUrls.results) {
        report += `${url.url || 'N/A'}: ${url.hits || 0} visitas\n`;
      }
    }

    return report;
  }
}

export default WebFilterModule;

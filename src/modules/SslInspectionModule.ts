/**
 * Módulo de SSL/SSH Inspection (DPI) para FortiGate MCP
 * Gestiona perfiles de inspección SSL/TLS y SSH (Deep Packet Inspection)
 */

import { BaseModule } from './BaseModule';
import { FortiGateClient } from '../utils/FortiGateClient';
import { ChangeAnalyzer } from '../utils/ChangeAnalyzer';
import { 
  SslSshProfile, 
  SslInspectionConfig,
  SshInspectionConfig,
  SslExemption,
  FortiGateApiResponse,
  ValidationResult 
} from '../types';
import { logger } from '../utils/logger';

export class SslInspectionModule extends BaseModule {
  constructor(client: FortiGateClient, changeAnalyzer: ChangeAnalyzer) {
    super(client, changeAnalyzer, {
      name: 'ssl-ssh-profile',
      apiPath: '/api/v2/cmdb/firewall/ssl-ssh-profile',
      supportsCrud: true,
      supportsMonitoring: true
    });
  }

  /**
   * Obtiene todos los perfiles de inspección SSL/SSH
   */
  async getProfiles(params?: Record<string, any>): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.getAll<SslSshProfile>(params);
  }

  /**
   * Obtiene un perfil específico
   */
  async getProfile(name: string): Promise<SslSshProfile | null> {
    return this.getById<SslSshProfile>(name);
  }

  /**
   * Crea un nuevo perfil de inspección SSL/SSH
   */
  async createProfile(profile: SslSshProfile): Promise<FortiGateApiResponse<SslSshProfile>> {
    const validation = this.validateProfile(profile);
    if (!validation.valid) {
      throw new Error(`Validación de perfil fallida: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    return this.create<SslSshProfile>(profile);
  }

  /**
   * Actualiza un perfil de inspección SSL/SSH
   */
  async updateProfile(
    name: string, 
    profile: Partial<SslSshProfile>
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update<SslSshProfile>(name, profile);
  }

  /**
   * Elimina un perfil de inspección SSL/SSH
   */
  async deleteProfile(name: string): Promise<FortiGateApiResponse<any>> {
    return this.delete(name);
  }

  /**
   * Valida un perfil de inspección SSL/SSH
   */
  validateProfile(profile: SslSshProfile): ValidationResult {
    const errors: any[] = [];
    const warnings: any[] = [];

    if (!profile.name) {
      errors.push({
        field: 'name',
        message: 'El nombre del perfil es requerido',
        code: 'SSL_PROFILE_NAME_REQUIRED'
      });
    }

    // Validar configuración SSL
    if (profile.ssl) {
      if (profile.ssl.ssl_min_ver && profile.ssl.ssl_max_ver) {
        const minVersions = ['ssl-3.0', 'tls-1.0', 'tls-1.1', 'tls-1.2', 'tls-1.3'];
        const minIndex = minVersions.indexOf(profile.ssl.ssl_min_ver);
        const maxIndex = minVersions.indexOf(profile.ssl.ssl_max_ver);
        
        if (minIndex > maxIndex) {
          errors.push({
            field: 'ssl.ssl_min_ver',
            message: 'La versión mínima SSL/TLS no puede ser mayor que la versión máxima',
            code: 'INVALID_SSL_VERSION_RANGE'
          });
        }
      }
    }

    // Advertir si no hay certificado CA configurado para deep inspection
    if ((profile.ssl?.status === 'deep-inspection' || 
         profile.https?.status === 'deep-inspection') && 
        !profile.caname) {
      warnings.push({
        field: 'caname',
        message: 'No se ha configurado un certificado CA para deep inspection',
        suggestion: 'Configure un certificado CA válido para evitar errores de certificado en los clientes'
      });
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Configura inspección SSL para un protocolo
   */
  async configureSslInspection(
    profileName: string,
    protocol: 'ssl' | 'https' | 'ftps' | 'imaps' | 'pop3s' | 'smtps' | 'dot',
    config: Partial<SslInspectionConfig>
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = {};
    update[protocol] = config;
    return this.update(profileName, update);
  }

  /**
   * Configura inspección SSH
   */
  async configureSshInspection(
    profileName: string,
    config: Partial<SshInspectionConfig>
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update(profileName, { ssh: config });
  }

  /**
   * Establece el modo de inspección para HTTPS
   */
  async setHttpsInspectionMode(
    profileName: string,
    mode: 'disable' | 'certificate-inspection' | 'deep-inspection'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update(profileName, {
      https: { status: mode }
    });
  }

  /**
   * Configura el certificado CA para inspección
   */
  async setCaCertificate(
    profileName: string,
    caName: string,
    untrustedCaName?: string
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = { caname: caName };
    if (untrustedCaName) {
      update.untrusted_caname = untrustedCaName;
    }
    return this.update(profileName, update);
  }

  /**
   * Agrega una exención de inspección
   */
  async addExemption(
    profileName: string,
    exemption: SslExemption
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const exemptions = profile.exemptions || [];
    
    // Asignar ID si no tiene
    if (exemption.id === undefined) {
      exemption.id = exemptions.length > 0 ? Math.max(...exemptions.map(e => e.id)) + 1 : 1;
    }

    exemptions.push(exemption);
    return this.update(profileName, { exemptions });
  }

  /**
   * Elimina una exención de inspección
   */
  async removeExemption(
    profileName: string,
    exemptionId: number
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const profile = await this.getProfile(profileName);
    if (!profile) {
      throw new Error(`Perfil no encontrado: ${profileName}`);
    }

    const exemptions = (profile.exemptions || []).filter(e => e.id !== exemptionId);
    return this.update(profileName, { exemptions });
  }

  /**
   * Agrega una exención por dirección
   */
  async addAddressExemption(
    profileName: string,
    addresses: string[],
    isIpv6: boolean = false
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const exemption: SslExemption = {
      id: 0, // Se asignará automáticamente
      q_origin_key: '0',
      type: isIpv6 ? 'address6' : 'address',
      address: isIpv6 ? undefined : addresses,
      address6: isIpv6 ? addresses : undefined
    };

    return this.addExemption(profileName, exemption);
  }

  /**
   * Agrega una exención por FQDN wildcard
   */
  async addWildcardFqdnExemption(
    profileName: string,
    wildcards: string[]
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const exemption: SslExemption = {
      id: 0,
      q_origin_key: '0',
      type: 'wildcard-fqdn',
      wildcard_fqdn: wildcards
    };

    return this.addExemption(profileName, exemption);
  }

  /**
   * Agrega una exención por categoría FortiGuard
   */
  async addFortiguardCategoryExemption(
    profileName: string,
    categories: number[]
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const exemption: SslExemption = {
      id: 0,
      q_origin_key: '0',
      type: 'fortiguard-category',
      fortiguard_category: categories
    };

    return this.addExemption(profileName, exemption);
  }

  /**
   * Configura versiones SSL/TLS soportadas
   */
  async setSslVersions(
    profileName: string,
    protocol: 'ssl' | 'https' | 'ftps' | 'imaps' | 'pop3s' | 'smtps',
    minVersion: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3',
    maxVersion: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = {};
    update[protocol] = {
      ssl_min_ver: minVersion,
      ssl_max_ver: maxVersion
    };
    return this.update(profileName, update);
  }

  /**
   * Configura manejo de certificados no confiables
   */
  async setUntrustedCertHandling(
    profileName: string,
    protocol: 'ssl' | 'https' | 'ftps' | 'imaps' | 'pop3s' | 'smtps',
    action: 'allow' | 'block' | 'ignore'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = {};
    update[protocol] = {
      untrusted_cert: action
    };
    return this.update(profileName, update);
  }

  /**
   * Configura manejo de certificados de cliente
   */
  async setClientCertHandling(
    profileName: string,
    protocol: 'ssl' | 'https' | 'ftps' | 'imaps' | 'pop3s' | 'smtps',
    action: 'bypass' | 'inspect' | 'block'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = {};
    update[protocol] = {
      client_cert_request: action
    };
    return this.update(profileName, update);
  }

  /**
   * Configura manejo de errores de validación de certificado
   */
  async setCertValidationHandling(
    profileName: string,
    protocol: 'ssl' | 'https' | 'ftps' | 'imaps' | 'pop3s' | 'smtps',
    options: {
      allowInvalidServerCert?: 'allow' | 'block';
      allowRevokedServerCert?: 'allow' | 'block';
      allowExpiredServerCert?: 'allow' | 'block';
    }
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const update: any = {};
    update[protocol] = {};
    
    if (options.allowInvalidServerCert) {
      update[protocol].invalid_server_cert = options.allowInvalidServerCert;
    }
    if (options.allowRevokedServerCert) {
      update[protocol].revoked_server_cert = options.allowRevokedServerCert;
    }
    if (options.allowExpiredServerCert) {
      update[protocol].expired_server_cert = options.allowExpiredServerCert;
    }
    
    return this.update(profileName, update);
  }

  /**
   * Habilita/deshabilita RPC sobre HTTPS
   */
  async setRpcOverHttps(
    profileName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update(profileName, { rpc_over_https: enabled });
  }

  /**
   * Habilita/deshabilita MAPI sobre HTTPS
   */
  async setMapiOverHttps(
    profileName: string,
    enabled: 'enable' | 'disable'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update(profileName, { mapi_over_https: enabled });
  }

  /**
   * Configura ALPN soportado
   */
  async setSupportedAlpn(
    profileName: string,
    alpn: 'none' | 'http1-1' | 'http2' | 'http1-1-http2'
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.update(profileName, { supported_alpn: alpn });
  }

  /**
   * Obtiene las estadísticas de inspección SSL
   */
  async getStatistics(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('statistics');
  }

  /**
   * Obtiene las sesiones SSL inspeccionadas
   */
  async getInspectedSessions(params?: {
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('sessions', params);
  }

  /**
   * Obtiene los certificados detectados
   */
  async getDetectedCertificates(params?: {
    limit?: number;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('certificates', params);
  }

  /**
   * Obtiene las anomalías SSL detectadas
   */
  async getSslAnomalies(params?: {
    since?: string;
    until?: string;
  }): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('anomalies', params);
  }

  /**
   * Crea un perfil de inspección profunda recomendado
   */
  async createDeepInspectionProfile(
    name: string,
    caCertificate: string
  ): Promise<FortiGateApiResponse<SslSshProfile>> {
    const profile: SslSshProfile = {
      name,
      comment: 'Perfil de deep inspection recomendado',
      ssl_anomalies_log: 'enable',
      ssl_exemptions_log: 'enable',
      ssl_negotiation_log: 'enable',
      extended_log: 'disable',
      rpc_over_https: 'enable',
      mapi_over_https: 'enable',
      supported_alpn: 'http1-1-http2',
      use_ssl_server: 'disable',
      caname: caCertificate,
      https: {
        status: 'deep-inspection',
        ssl_min_ver: 'tls-1.2',
        ssl_max_ver: 'tls-1.3',
        invalid_server_cert: 'block',
        revoked_server_cert: 'block',
        expired_server_cert: 'block',
        untrusted_cert: 'block',
        unsupported_ssl_cipher: 'block',
        unsupported_ssl_negotiation: 'block',
        client_cert_request: 'inspect',
        unsupported_ssl_version: 'block',
        unknown_ssl_version: 'block',
        ssl_negotiation_log: 'enable'
      },
      ftps: {
        status: 'deep-inspection',
        ssl_min_ver: 'tls-1.2',
        ssl_max_ver: 'tls-1.3'
      },
      imaps: {
        status: 'deep-inspection',
        ssl_min_ver: 'tls-1.2',
        ssl_max_ver: 'tls-1.3'
      },
      pop3s: {
        status: 'deep-inspection',
        ssl_min_ver: 'tls-1.2',
        ssl_max_ver: 'tls-1.3'
      },
      smtps: {
        status: 'deep-inspection',
        ssl_min_ver: 'tls-1.2',
        ssl_max_ver: 'tls-1.3'
      },
      ssh: {
        status: 'deep-inspection',
        ssh_policy_check: 'ssh',
        ssh_algorithm: 'high-encryption',
        unsupported_version: 'block'
      }
    };

    return this.createProfile(profile);
  }

  /**
   * Crea un perfil de inspección de certificado (sin desencriptación)
   */
  async createCertificateInspectionProfile(name: string): Promise<FortiGateApiResponse<SslSshProfile>> {
    const profile: SslSshProfile = {
      name,
      comment: 'Perfil de certificate inspection (sin desencriptación)',
      ssl_anomalies_log: 'enable',
      ssl_exemptions_log: 'enable',
      ssl_negotiation_log: 'enable',
      extended_log: 'disable',
      rpc_over_https: 'enable',
      mapi_over_https: 'enable',
      supported_alpn: 'http1-1-http2',
      https: {
        status: 'certificate-inspection',
        ssl_min_ver: 'tls-1.0',
        ssl_max_ver: 'tls-1.3'
      },
      ftps: {
        status: 'certificate-inspection'
      },
      imaps: {
        status: 'certificate-inspection'
      },
      pop3s: {
        status: 'certificate-inspection'
      },
      smtps: {
        status: 'certificate-inspection'
      },
      ssh: {
        status: 'disable'
      }
    };

    return this.createProfile(profile);
  }

  /**
   * Obtiene perfiles predefinidos
   */
  async getDefaultProfiles(): Promise<FortiGateApiResponse<SslSshProfile>> {
    return this.getAll({ filter: 'default==enable' });
  }

  /**
   * Genera un informe de actividad de inspección SSL
   */
  async generateReport(params?: {
    since?: string;
    until?: string;
  }): Promise<string> {
    const anomalies = await this.getSslAnomalies(params);
    const stats = await this.getStatistics();
    
    let report = '=== INFORME DE INSPECCIÓN SSL/SSH ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n`;
    report += `Anomalías detectadas: ${anomalies.size}\n\n`;

    if (stats.results && stats.results[0]) {
      const s = stats.results[0];
      report += '=== ESTADÍSTICAS ===\n';
      report += `Sesiones inspeccionadas: ${s.sessions_inspected || 0}\n`;
      report += `Certificados validados: ${s.certificates_validated || 0}\n`;
      report += `Conexiones bloqueadas: ${s.connections_blocked || 0}\n`;
    }

    if (anomalies.results && anomalies.results.length > 0) {
      report += '\n=== ANOMALÍAS ===\n';
      for (const a of anomalies.results) {
        report += `Fecha: ${a.date || 'N/A'}\n`;
        report += `Tipo: ${a.type || 'N/A'}\n`;
        report += `Severidad: ${a.severity || 'N/A'}\n`;
        report += `Origen: ${a.srcip || 'N/A'} -> ${a.dstip || 'N/A'}\n\n`;
      }
    }

    return report;
  }

  /**
   * Obtiene el uso de recursos del motor de inspección
   */
  async getResourceUsage(): Promise<FortiGateApiResponse<any>> {
    return this.getMonitor('resource-usage');
  }
}

export default SslInspectionModule;

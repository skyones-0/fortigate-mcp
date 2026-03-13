/**
 * Cliente HTTP para FortiGate API V7.6
 * Maneja autenticación, peticiones y respuestas
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import https from 'https';
import {
  FortiGateConfig,
  FortiGateResponse,
  FortiGateErrorResponse,
  FirewallPolicy,
  AddressObject,
  AddressGroup,
  ServiceObject,
  ServiceGroup,
  VIP,
  VIPGroup,
  Interface,
  StaticRoute,
  SystemInfo,
  VDOM,
  UserLocal,
  UserGroup,
  SSLVPNSettings,
  LogSettings,
  AntivirusProfile,
  WebFilterProfile,
  DNSFilterProfile,
  ApplicationControlProfile,
  IPSSensor,
  SSLSSHProfile,
  HAConfig,
  SystemAdmin,
  SystemGlobal,
  FortiGuardConfig,
  LogFortiAnalyzerSettings,
  LogSyslogSettings,
  LogDiskSettings,
  LogEventFilter,
  LogTrafficFilter,
  SDWANConfig,
  Zone,
  Certificate,
  VPNIPsecPhase1,
  VPNIPsecPhase2,
  VPNSSLPortal,
  WAFProfile,
  ProxyPolicy,
  TrafficShaper,
  TrafficShaperPerIP,
  FirewallScheduleRecurring,
  FirewallScheduleOnetime,
  FirewallScheduleGroup,
  FirewallLocalInPolicy,
  FirewallMulticastPolicy,
  FirewallDNAT,
  CentralNAT,
  SystemAPIUser,
  SystemSNMPUser,
  SystemSNMPCommunity,
  SystemAutomationStitch,
  SystemAutomationTrigger,
  SystemReplacemsgGroup,
  SystemSessionHelper,
  SystemDHCPServer,
  SystemSettings,
  SystemLinkMonitor,
  SystemVirtualSwitch,
  SystemVirtualWirePair,
  SystemVxlan,
  SystemGRETunnel,
  SystemPPPoEInterface,
  SystemGeoipOverride,
  SystemFIPSCC,
} from '../types/fortigate.js';

// Clase de error personalizada para FortiGate
export class FortiGateError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public responseData?: unknown
  ) {
    super(message);
    this.name = 'FortiGateError';
  }
}

// Cliente FortiGate
export class FortiGateClient {
  private client: AxiosInstance;
  private config: FortiGateConfig;
  private sessionKey: string | null = null;
  private isConnected = false;

  constructor(config: FortiGateConfig) {
    this.config = {
      port: 443,
      https: true,
      verifySsl: false,
      timeout: 30000,
      ...config,
    };

    // Validar configuración
    if (!this.config.host) {
      throw new FortiGateError('FORTIGATE_HOST es requerido');
    }
    if (!this.config.apiToken) {
      throw new FortiGateError('FORTIGATE_API_TOKEN (o FORTIGATE_TOKEN) es requerido');
    }

    const baseURL = `${this.config.https ? 'https' : 'http'}://${this.config.host}:${this.config.port}`;

    this.client = axios.create({
      baseURL,
      timeout: this.config.timeout,
      httpsAgent: this.config.verifySsl ? undefined : new https.Agent({ 
        rejectUnauthorized: false,
        keepAlive: true,
        timeout: this.config.timeout,
      }),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      maxRedirects: 5,
      validateStatus: (status) => status < 500, // No rechazar errores 4xx, los manejamos nosotros
    });

    // Interceptor para agregar token de autenticación
    this.client.interceptors.request.use(
      (config) => {
        if (this.sessionKey) {
          config.headers['Authorization'] = `Bearer ${this.sessionKey}`;
        } else if (this.config.apiToken) {
          config.headers['Authorization'] = `Bearer ${this.config.apiToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Interceptor para manejar errores
    this.client.interceptors.response.use(
      (response) => {
        // Verificar si la respuesta contiene un error de FortiGate
        if (response.data && typeof response.data === 'object') {
          const data = response.data as FortiGateErrorResponse;
          if (data.http_method && data.status === 'error') {
            const errorMessage = (data as unknown as Record<string, string>).error || 
                                'Unknown FortiGate error';
            throw new FortiGateError(errorMessage, response.status, data);
          }
        }
        return response;
      },
      (error: AxiosError<FortiGateErrorResponse>) => {
        if (error.response) {
          const status = error.response.status;
          const data = error.response.data;
          
          let errorMessage = `FortiGate API Error: ${status}`;
          if (typeof data === 'object' && data !== null) {
            if ('error' in data && typeof data.error === 'string') {
              errorMessage = data.error;
            } else if ('message' in data && typeof data.message === 'string') {
              errorMessage = data.message;
            } else if ('cli_error' in data && typeof data.cli_error === 'string') {
              errorMessage = data.cli_error;
            }
          }
          
          throw new FortiGateError(errorMessage, status, data);
        } else if (error.request) {
          throw new FortiGateError('No response from FortiGate. Check network connectivity.');
        } else {
          throw new FortiGateError(`Request error: ${error.message}`);
        }
      }
    );
  }

  // Método para login con usuario/contraseña (alternativa al token)
  async login(username: string, password: string): Promise<void> {
    try {
      const response = await this.client.post<FortiGateResponse<{ token?: string }>>('/api/v2/authentication', {
        username,
        password,
        client_flags: 0,
      });

      if (response.data.results?.token) {
        this.sessionKey = response.data.results.token;
      }
    } catch (error) {
      if (error instanceof FortiGateError) {
        throw error;
      }
      throw new FortiGateError('Login failed');
    }
  }

  // Método para logout
  async logout(): Promise<void> {
    if (this.sessionKey) {
      try {
        await this.client.post('/api/v2/deauthentication');
      } finally {
        this.sessionKey = null;
      }
    }
  }

  // Método genérico para peticiones GET
  async get<T>(path: string, params?: Record<string, unknown>): Promise<FortiGateResponse<T>> {
    const response = await this.client.get<FortiGateResponse<T>>(path, { params });
    return response.data;
  }

  // Método genérico para peticiones POST
  async post<T>(path: string, data?: unknown, params?: Record<string, unknown>): Promise<FortiGateResponse<T>> {
    const response = await this.client.post<FortiGateResponse<T>>(path, data, { params });
    return response.data;
  }

  // Método genérico para peticiones PUT
  async put<T>(path: string, data?: unknown, params?: Record<string, unknown>): Promise<FortiGateResponse<T>> {
    const response = await this.client.put<FortiGateResponse<T>>(path, data, { params });
    return response.data;
  }

  // Método genérico para peticiones DELETE
  async delete<T>(path: string, params?: Record<string, unknown>): Promise<FortiGateResponse<T>> {
    const response = await this.client.delete<FortiGateResponse<T>>(path, { params });
    return response.data;
  }

  // ==================== SYSTEM INFO ====================
  
  async getSystemStatus(): Promise<SystemInfo> {
    try {
      const response = await this.get<SystemInfo>('/api/v2/monitor/system/status');
      this.isConnected = true;
      return response.results;
    } catch (error) {
      this.isConnected = false;
      if (error instanceof FortiGateError) {
        throw error;
      }
      throw new FortiGateError(`Failed to get system status: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  async getSystemTime(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/time');
    return response.results;
  }

  async getSystemConfig(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/config');
    return response.results;
  }

  async getSystemPerformance(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/performance');
    return response.results;
  }

  async getSystemResources(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/resource/usage');
    return response.results;
  }

  async getSystemInterfaces(): Promise<Interface[]> {
    const response = await this.get<Interface[]>('/api/v2/cmdb/system/interface');
    return response.results;
  }

  async getSystemGlobal(): Promise<SystemGlobal> {
    const response = await this.get<SystemGlobal>('/api/v2/cmdb/system/global');
    return response.results;
  }

  async updateSystemGlobal(data: Partial<SystemGlobal>): Promise<SystemGlobal> {
    const response = await this.put<SystemGlobal>('/api/v2/cmdb/system/global', data);
    return response.results;
  }

  async getSystemSettings(): Promise<SystemSettings> {
    const response = await this.get<SystemSettings>('/api/v2/cmdb/system/settings');
    return response.results;
  }

  async updateSystemSettings(data: Partial<SystemSettings>): Promise<SystemSettings> {
    const response = await this.put<SystemSettings>('/api/v2/cmdb/system/settings', data);
    return response.results;
  }

  async getSystemAdministrators(): Promise<SystemAdmin[]> {
    const response = await this.get<SystemAdmin[]>('/api/v2/cmdb/system/admin');
    return response.results;
  }

  async createSystemAdministrator(data: SystemAdmin): Promise<SystemAdmin> {
    const response = await this.post<SystemAdmin>('/api/v2/cmdb/system/admin', data);
    return response.results;
  }

  async updateSystemAdministrator(name: string, data: Partial<SystemAdmin>): Promise<SystemAdmin> {
    const response = await this.put<SystemAdmin>(`/api/v2/cmdb/system/admin/${name}`, data);
    return response.results;
  }

  async deleteSystemAdministrator(name: string): Promise<void> {
    await this.delete(`/api/v2/cmdb/system/admin/${name}`);
  }

  // ==================== VDOM ====================

  async getVDOMs(): Promise<VDOM[]> {
    const response = await this.get<VDOM[]>('/api/v2/cmdb/system/vdom');
    return response.results;
  }

  async createVDOM(data: VDOM): Promise<VDOM> {
    const response = await this.post<VDOM>('/api/v2/cmdb/system/vdom', data);
    return response.results;
  }

  async deleteVDOM(name: string): Promise<void> {
    await this.delete(`/api/v2/cmdb/system/vdom/${name}`);
  }

  // ==================== FIREWALL POLICIES ====================

  async getFirewallPolicies(vdom?: string): Promise<FirewallPolicy[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<FirewallPolicy[]>('/api/v2/cmdb/firewall/policy', params);
    return response.results;
  }

  async getFirewallPolicy(policyId: number, vdom?: string): Promise<FirewallPolicy> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<FirewallPolicy>(`/api/v2/cmdb/firewall/policy/${policyId}`, params);
    return response.results;
  }

  async createFirewallPolicy(data: FirewallPolicy, vdom?: string): Promise<FirewallPolicy> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<FirewallPolicy>('/api/v2/cmdb/firewall/policy', data, params);
    return response.results;
  }

  async updateFirewallPolicy(policyId: number, data: Partial<FirewallPolicy>, vdom?: string): Promise<FirewallPolicy> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<FirewallPolicy>(`/api/v2/cmdb/firewall/policy/${policyId}`, data, params);
    return response.results;
  }

  async deleteFirewallPolicy(policyId: number, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/policy/${policyId}`, params);
  }

  async moveFirewallPolicy(policyId: number, position: 'before' | 'after', targetId: number, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.put(`/api/v2/cmdb/firewall/policy/${policyId}`, {
      'policy-move': position,
      'policy-ref': targetId,
    }, params);
  }

  // ==================== ADDRESS OBJECTS ====================

  async getAddressObjects(vdom?: string): Promise<AddressObject[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<AddressObject[]>('/api/v2/cmdb/firewall/address', params);
    return response.results;
  }

  async getAddressObject(name: string, vdom?: string): Promise<AddressObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<AddressObject>(`/api/v2/cmdb/firewall/address/${name}`, params);
    return response.results;
  }

  async createAddressObject(data: AddressObject, vdom?: string): Promise<AddressObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<AddressObject>('/api/v2/cmdb/firewall/address', data, params);
    return response.results;
  }

  async updateAddressObject(name: string, data: Partial<AddressObject>, vdom?: string): Promise<AddressObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<AddressObject>(`/api/v2/cmdb/firewall/address/${name}`, data, params);
    return response.results;
  }

  async deleteAddressObject(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/address/${name}`, params);
  }

  // ==================== ADDRESS GROUPS ====================

  async getAddressGroups(vdom?: string): Promise<AddressGroup[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<AddressGroup[]>('/api/v2/cmdb/firewall/addrgrp', params);
    return response.results;
  }

  async createAddressGroup(data: AddressGroup, vdom?: string): Promise<AddressGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<AddressGroup>('/api/v2/cmdb/firewall/addrgrp', data, params);
    return response.results;
  }

  async updateAddressGroup(name: string, data: Partial<AddressGroup>, vdom?: string): Promise<AddressGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<AddressGroup>(`/api/v2/cmdb/firewall/addrgrp/${name}`, data, params);
    return response.results;
  }

  async deleteAddressGroup(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/addrgrp/${name}`, params);
  }

  // ==================== SERVICE OBJECTS ====================

  async getServiceObjects(vdom?: string): Promise<ServiceObject[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<ServiceObject[]>('/api/v2/cmdb/firewall.service/custom', params);
    return response.results;
  }

  async getServiceObject(name: string, vdom?: string): Promise<ServiceObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<ServiceObject>(`/api/v2/cmdb/firewall.service/custom/${name}`, params);
    return response.results;
  }

  async createServiceObject(data: ServiceObject, vdom?: string): Promise<ServiceObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<ServiceObject>('/api/v2/cmdb/firewall.service/custom', data, params);
    return response.results;
  }

  async updateServiceObject(name: string, data: Partial<ServiceObject>, vdom?: string): Promise<ServiceObject> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<ServiceObject>(`/api/v2/cmdb/firewall.service/custom/${name}`, data, params);
    return response.results;
  }

  async deleteServiceObject(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall.service/custom/${name}`, params);
  }

  // ==================== SERVICE GROUPS ====================

  async getServiceGroups(vdom?: string): Promise<ServiceGroup[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<ServiceGroup[]>('/api/v2/cmdb/firewall.service/group', params);
    return response.results;
  }

  async createServiceGroup(data: ServiceGroup, vdom?: string): Promise<ServiceGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<ServiceGroup>('/api/v2/cmdb/firewall.service/group', data, params);
    return response.results;
  }

  async updateServiceGroup(name: string, data: Partial<ServiceGroup>, vdom?: string): Promise<ServiceGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<ServiceGroup>(`/api/v2/cmdb/firewall.service/group/${name}`, data, params);
    return response.results;
  }

  async deleteServiceGroup(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall.service/group/${name}`, params);
  }

  // ==================== VIP (VIRTUAL IPs) ====================

  async getVIPs(vdom?: string): Promise<VIP[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VIP[]>('/api/v2/cmdb/firewall/vip', params);
    return response.results;
  }

  async getVIP(name: string, vdom?: string): Promise<VIP> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VIP>(`/api/v2/cmdb/firewall/vip/${name}`, params);
    return response.results;
  }

  async createVIP(data: VIP, vdom?: string): Promise<VIP> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<VIP>('/api/v2/cmdb/firewall/vip', data, params);
    return response.results;
  }

  async updateVIP(name: string, data: Partial<VIP>, vdom?: string): Promise<VIP> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<VIP>(`/api/v2/cmdb/firewall/vip/${name}`, data, params);
    return response.results;
  }

  async deleteVIP(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/vip/${name}`, params);
  }

  // ==================== VIP GROUPS ====================

  async getVIPGroups(vdom?: string): Promise<VIPGroup[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VIPGroup[]>('/api/v2/cmdb/firewall/vipgrp', params);
    return response.results;
  }

  async createVIPGroup(data: VIPGroup, vdom?: string): Promise<VIPGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<VIPGroup>('/api/v2/cmdb/firewall/vipgrp', data, params);
    return response.results;
  }

  async updateVIPGroup(name: string, data: Partial<VIPGroup>, vdom?: string): Promise<VIPGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<VIPGroup>(`/api/v2/cmdb/firewall/vipgrp/${name}`, data, params);
    return response.results;
  }

  async deleteVIPGroup(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/vipgrp/${name}`, params);
  }

  // ==================== ROUTING ====================

  async getStaticRoutes(vdom?: string): Promise<StaticRoute[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<StaticRoute[]>('/api/v2/cmdb/router/static', params);
    return response.results;
  }

  async createStaticRoute(data: StaticRoute, vdom?: string): Promise<StaticRoute> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<StaticRoute>('/api/v2/cmdb/router/static', data, params);
    return response.results;
  }

  async updateStaticRoute(seqNum: number, data: Partial<StaticRoute>, vdom?: string): Promise<StaticRoute> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<StaticRoute>(`/api/v2/cmdb/router/static/${seqNum}`, data, params);
    return response.results;
  }

  async deleteStaticRoute(seqNum: number, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/router/static/${seqNum}`, params);
  }

  async getRoutingTable(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/router/ipv4', params);
    return response.results;
  }

  async getBGPConfig(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/cmdb/router/bgp', params);
    return response.results;
  }

  async getOSPFConfig(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/cmdb/router/ospf', params);
    return response.results;
  }

  // ==================== USERS & GROUPS ====================

  async getLocalUsers(vdom?: string): Promise<UserLocal[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<UserLocal[]>('/api/v2/cmdb/user/local', params);
    return response.results;
  }

  async createLocalUser(data: UserLocal, vdom?: string): Promise<UserLocal> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<UserLocal>('/api/v2/cmdb/user/local', data, params);
    return response.results;
  }

  async updateLocalUser(name: string, data: Partial<UserLocal>, vdom?: string): Promise<UserLocal> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<UserLocal>(`/api/v2/cmdb/user/local/${name}`, data, params);
    return response.results;
  }

  async deleteLocalUser(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/user/local/${name}`, params);
  }

  async getUserGroups(vdom?: string): Promise<UserGroup[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<UserGroup[]>('/api/v2/cmdb/user/group', params);
    return response.results;
  }

  async createUserGroup(data: UserGroup, vdom?: string): Promise<UserGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<UserGroup>('/api/v2/cmdb/user/group', data, params);
    return response.results;
  }

  async updateUserGroup(name: string, data: Partial<UserGroup>, vdom?: string): Promise<UserGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<UserGroup>(`/api/v2/cmdb/user/group/${name}`, data, params);
    return response.results;
  }

  async deleteUserGroup(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/user/group/${name}`, params);
  }

  // ==================== SSL VPN ====================

  async getSSLVPNSettings(vdom?: string): Promise<SSLVPNSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<SSLVPNSettings>('/api/v2/cmdb/vpn.ssl/settings', params);
    return response.results;
  }

  async updateSSLVPNSettings(data: Partial<SSLVPNSettings>, vdom?: string): Promise<SSLVPNSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<SSLVPNSettings>('/api/v2/cmdb/vpn.ssl/settings', data, params);
    return response.results;
  }

  async getSSLVPNPortals(vdom?: string): Promise<VPNSSLPortal[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VPNSSLPortal[]>('/api/v2/cmdb/vpn.ssl.web/portal', params);
    return response.results;
  }

  async createSSLVPNPortal(data: VPNSSLPortal, vdom?: string): Promise<VPNSSLPortal> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<VPNSSLPortal>('/api/v2/cmdb/vpn.ssl.web/portal', data, params);
    return response.results;
  }

  async updateSSLVPNPortal(name: string, data: Partial<VPNSSLPortal>, vdom?: string): Promise<VPNSSLPortal> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<VPNSSLPortal>(`/api/v2/cmdb/vpn.ssl.web/portal/${name}`, data, params);
    return response.results;
  }

  async deleteSSLVPNPortal(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/vpn.ssl.web/portal/${name}`, params);
  }

  async getSSLVPNSessions(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/vpn/ssl', params);
    return response.results;
  }

  // ==================== IPsec VPN ====================

  async getIPsecPhase1(vdom?: string): Promise<VPNIPsecPhase1[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VPNIPsecPhase1[]>('/api/v2/cmdb/vpn.ipsec/phase1-interface', params);
    return response.results;
  }

  async createIPsecPhase1(data: VPNIPsecPhase1, vdom?: string): Promise<VPNIPsecPhase1> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<VPNIPsecPhase1>('/api/v2/cmdb/vpn.ipsec/phase1-interface', data, params);
    return response.results;
  }

  async updateIPsecPhase1(name: string, data: Partial<VPNIPsecPhase1>, vdom?: string): Promise<VPNIPsecPhase1> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<VPNIPsecPhase1>(`/api/v2/cmdb/vpn.ipsec/phase1-interface/${name}`, data, params);
    return response.results;
  }

  async deleteIPsecPhase1(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/vpn.ipsec/phase1-interface/${name}`, params);
  }

  async getIPsecPhase2(vdom?: string): Promise<VPNIPsecPhase2[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<VPNIPsecPhase2[]>('/api/v2/cmdb/vpn.ipsec/phase2-interface', params);
    return response.results;
  }

  async createIPsecPhase2(data: VPNIPsecPhase2, vdom?: string): Promise<VPNIPsecPhase2> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<VPNIPsecPhase2>('/api/v2/cmdb/vpn.ipsec/phase2-interface', data, params);
    return response.results;
  }

  async updateIPsecPhase2(name: string, data: Partial<VPNIPsecPhase2>, vdom?: string): Promise<VPNIPsecPhase2> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<VPNIPsecPhase2>(`/api/v2/cmdb/vpn.ipsec/phase2-interface/${name}`, data, params);
    return response.results;
  }

  async deleteIPsecPhase2(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/vpn.ipsec/phase2-interface/${name}`, params);
  }

  async getIPsecTunnels(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/vpn/ipsec', params);
    return response.results;
  }

  // ==================== SECURITY PROFILES ====================

  async getAntivirusProfiles(vdom?: string): Promise<AntivirusProfile[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<AntivirusProfile[]>('/api/v2/cmdb/antivirus/profile', params);
    return response.results;
  }

  async createAntivirusProfile(data: AntivirusProfile, vdom?: string): Promise<AntivirusProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<AntivirusProfile>('/api/v2/cmdb/antivirus/profile', data, params);
    return response.results;
  }

  async updateAntivirusProfile(name: string, data: Partial<AntivirusProfile>, vdom?: string): Promise<AntivirusProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<AntivirusProfile>(`/api/v2/cmdb/antivirus/profile/${name}`, data, params);
    return response.results;
  }

  async deleteAntivirusProfile(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/antivirus/profile/${name}`, params);
  }

  async getWebFilterProfiles(vdom?: string): Promise<WebFilterProfile[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<WebFilterProfile[]>('/api/v2/cmdb/webfilter/profile', params);
    return response.results;
  }

  async createWebFilterProfile(data: WebFilterProfile, vdom?: string): Promise<WebFilterProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<WebFilterProfile>('/api/v2/cmdb/webfilter/profile', data, params);
    return response.results;
  }

  async updateWebFilterProfile(name: string, data: Partial<WebFilterProfile>, vdom?: string): Promise<WebFilterProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<WebFilterProfile>(`/api/v2/cmdb/webfilter/profile/${name}`, data, params);
    return response.results;
  }

  async deleteWebFilterProfile(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/webfilter/profile/${name}`, params);
  }

  async getDNSFilterProfiles(vdom?: string): Promise<DNSFilterProfile[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<DNSFilterProfile[]>('/api/v2/cmdb/dnsfilter/profile', params);
    return response.results;
  }

  async createDNSFilterProfile(data: DNSFilterProfile, vdom?: string): Promise<DNSFilterProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<DNSFilterProfile>('/api/v2/cmdb/dnsfilter/profile', data, params);
    return response.results;
  }

  async updateDNSFilterProfile(name: string, data: Partial<DNSFilterProfile>, vdom?: string): Promise<DNSFilterProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<DNSFilterProfile>(`/api/v2/cmdb/dnsfilter/profile/${name}`, data, params);
    return response.results;
  }

  async deleteDNSFilterProfile(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/dnsfilter/profile/${name}`, params);
  }

  async getApplicationControlProfiles(vdom?: string): Promise<ApplicationControlProfile[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<ApplicationControlProfile[]>('/api/v2/cmdb/application/list', params);
    return response.results;
  }

  async createApplicationControlProfile(data: ApplicationControlProfile, vdom?: string): Promise<ApplicationControlProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<ApplicationControlProfile>('/api/v2/cmdb/application/list', data, params);
    return response.results;
  }

  async updateApplicationControlProfile(name: string, data: Partial<ApplicationControlProfile>, vdom?: string): Promise<ApplicationControlProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<ApplicationControlProfile>(`/api/v2/cmdb/application/list/${name}`, data, params);
    return response.results;
  }

  async deleteApplicationControlProfile(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/application/list/${name}`, params);
  }

  async getIPSSensors(vdom?: string): Promise<IPSSensor[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<IPSSensor[]>('/api/v2/cmdb/ips/sensor', params);
    return response.results;
  }

  async createIPSSensor(data: IPSSensor, vdom?: string): Promise<IPSSensor> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<IPSSensor>('/api/v2/cmdb/ips/sensor', data, params);
    return response.results;
  }

  async updateIPSSensor(name: string, data: Partial<IPSSensor>, vdom?: string): Promise<IPSSensor> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<IPSSensor>(`/api/v2/cmdb/ips/sensor/${name}`, data, params);
    return response.results;
  }

  async deleteIPSSensor(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/ips/sensor/${name}`, params);
  }

  async getSSLSSHProfiles(vdom?: string): Promise<SSLSSHProfile[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<SSLSSHProfile[]>('/api/v2/cmdb/firewall/ssl-ssh-profile', params);
    return response.results;
  }

  async createSSLSSHProfile(data: SSLSSHProfile, vdom?: string): Promise<SSLSSHProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<SSLSSHProfile>('/api/v2/cmdb/firewall/ssl-ssh-profile', data, params);
    return response.results;
  }

  async updateSSLSSHProfile(name: string, data: Partial<SSLSSHProfile>, vdom?: string): Promise<SSLSSHProfile> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<SSLSSHProfile>(`/api/v2/cmdb/firewall/ssl-ssh-profile/${name}`, data, params);
    return response.results;
  }

  async deleteSSLSSHProfile(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall/ssl-ssh-profile/${name}`, params);
  }

  // ==================== LOGGING ====================

  async getLogSettings(vdom?: string): Promise<LogSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogSettings>('/api/v2/cmdb/log/gui', params);
    return response.results;
  }

  async updateLogSettings(data: Partial<LogSettings>, vdom?: string): Promise<LogSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogSettings>('/api/v2/cmdb/log/gui', data, params);
    return response.results;
  }

  async getLogFortiAnalyzerSettings(vdom?: string): Promise<LogFortiAnalyzerSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogFortiAnalyzerSettings>('/api/v2/cmdb/log.fortianalyzer/setting', params);
    return response.results;
  }

  async updateLogFortiAnalyzerSettings(data: Partial<LogFortiAnalyzerSettings>, vdom?: string): Promise<LogFortiAnalyzerSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogFortiAnalyzerSettings>('/api/v2/cmdb/log.fortianalyzer/setting', data, params);
    return response.results;
  }

  async getLogSyslogSettings(vdom?: string): Promise<LogSyslogSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogSyslogSettings>('/api/v2/cmdb/log.syslogd/setting', params);
    return response.results;
  }

  async updateLogSyslogSettings(data: Partial<LogSyslogSettings>, vdom?: string): Promise<LogSyslogSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogSyslogSettings>('/api/v2/cmdb/log.syslogd/setting', data, params);
    return response.results;
  }

  async getLogDiskSettings(vdom?: string): Promise<LogDiskSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogDiskSettings>('/api/v2/cmdb/log.disk/setting', params);
    return response.results;
  }

  async updateLogDiskSettings(data: Partial<LogDiskSettings>, vdom?: string): Promise<LogDiskSettings> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogDiskSettings>('/api/v2/cmdb/log.disk/setting', data, params);
    return response.results;
  }

  async getLogEventFilter(vdom?: string): Promise<LogEventFilter> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogEventFilter>('/api/v2/cmdb/log.eventfilter/setting', params);
    return response.results;
  }

  async updateLogEventFilter(data: Partial<LogEventFilter>, vdom?: string): Promise<LogEventFilter> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogEventFilter>('/api/v2/cmdb/log.eventfilter/setting', data, params);
    return response.results;
  }

  async getLogTrafficFilter(vdom?: string): Promise<LogTrafficFilter> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<LogTrafficFilter>('/api/v2/cmdb/log.trafficfilter/setting', params);
    return response.results;
  }

  async updateLogTrafficFilter(data: Partial<LogTrafficFilter>, vdom?: string): Promise<LogTrafficFilter> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<LogTrafficFilter>('/api/v2/cmdb/log.trafficfilter/setting', data, params);
    return response.results;
  }

  // ==================== MONITORING ====================

  async getSystemSessions(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/firewall/session', params);
    return response.results;
  }

  async getTopSessions(vdom?: string, count: number = 10): Promise<unknown> {
    const params = vdom ? { vdom, count } : { count };
    const response = await this.get<unknown>('/api/v2/monitor/firewall/session/top', params);
    return response.results;
  }

  async clearAllSessions(vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.post('/api/v2/monitor/firewall/session/delete', {}, params);
  }

  async clearSession(sessionId: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.post('/api/v2/monitor/firewall/session/delete', { session_id: sessionId }, params);
  }

  async getSystemAlerts(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/system/alert', params);
    return response.results;
  }

  async getLicenseStatus(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/license/status');
    return response.results;
  }

  async getFortiGuardStatus(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/fortiguard');
    return response.results;
  }

  // ==================== HA ====================

  async getHAConfig(): Promise<HAConfig> {
    const response = await this.get<HAConfig>('/api/v2/cmdb/system/ha');
    return response.results;
  }

  async updateHAConfig(data: Partial<HAConfig>): Promise<HAConfig> {
    const response = await this.put<HAConfig>('/api/v2/cmdb/system/ha', data);
    return response.results;
  }

  async getHAStatus(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/ha');
    return response.results;
  }

  async getHAPeerInfo(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/ha-peer');
    return response.results;
  }

  async executeHAFailover(peerSerial: string): Promise<void> {
    await this.post('/api/v2/monitor/system/ha/failover', { peer_serial: peerSerial });
  }

  // ==================== BACKUP & RESTORE ====================

  async backupConfig(scope: 'global' | 'vdom' = 'global'): Promise<string> {
    const response = await this.get<string>('/api/v2/monitor/system/config/backup', {
      scope,
      destination: 'file',
    });
    return response.results;
  }

  async restoreConfig(configData: string, scope: 'global' | 'vdom' = 'global'): Promise<void> {
    await this.post('/api/v2/monitor/system/config/restore', {
      config: configData,
      scope,
    });
  }

  // ==================== EXECUTE COMMANDS ====================

  async executeCLICommand(command: string, vdom?: string): Promise<string> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<{ result: string }>('/api/v2/monitor/system/cli', {
      command,
    }, params);
    return response.results.result;
  }

  // ==================== REBOOT & SHUTDOWN ====================

  async reboot(): Promise<void> {
    await this.post('/api/v2/monitor/system/os/reboot');
  }

  async shutdown(): Promise<void> {
    await this.post('/api/v2/monitor/system/os/shutdown');
  }

  // ==================== FIRMWARE ====================

  async getFirmwareStatus(): Promise<unknown> {
    const response = await this.get<unknown>('/api/v2/monitor/system/firmware');
    return response.results;
  }

  async upgradeFirmware(filename: string): Promise<void> {
    await this.post('/api/v2/monitor/system/firmware/upgrade', {
      filename,
    });
  }

  // ==================== SD-WAN ====================

  async getSDWANConfig(vdom?: string): Promise<SDWANConfig> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<SDWANConfig>('/api/v2/cmdb/system/sdwan', params);
    return response.results;
  }

  async updateSDWANConfig(data: Partial<SDWANConfig>, vdom?: string): Promise<SDWANConfig> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<SDWANConfig>('/api/v2/cmdb/system/sdwan', data, params);
    return response.results;
  }

  async getSDWANStatus(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/virtual-wan/health-check', params);
    return response.results;
  }

  async getSDWANMembers(vdom?: string): Promise<unknown> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<unknown>('/api/v2/monitor/virtual-wan/members', params);
    return response.results;
  }

  // ==================== ZONES ====================

  async getZones(vdom?: string): Promise<Zone[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<Zone[]>('/api/v2/cmdb/system/zone', params);
    return response.results;
  }

  async createZone(data: Zone, vdom?: string): Promise<Zone> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<Zone>('/api/v2/cmdb/system/zone', data, params);
    return response.results;
  }

  async updateZone(name: string, data: Partial<Zone>, vdom?: string): Promise<Zone> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<Zone>(`/api/v2/cmdb/system/zone/${name}`, data, params);
    return response.results;
  }

  async deleteZone(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/system/zone/${name}`, params);
  }

  // ==================== SCHEDULES ====================

  async getSchedulesRecurring(vdom?: string): Promise<FirewallScheduleRecurring[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<FirewallScheduleRecurring[]>('/api/v2/cmdb/firewall.schedule/recurring', params);
    return response.results;
  }

  async createScheduleRecurring(data: FirewallScheduleRecurring, vdom?: string): Promise<FirewallScheduleRecurring> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<FirewallScheduleRecurring>('/api/v2/cmdb/firewall.schedule/recurring', data, params);
    return response.results;
  }

  async updateScheduleRecurring(name: string, data: Partial<FirewallScheduleRecurring>, vdom?: string): Promise<FirewallScheduleRecurring> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<FirewallScheduleRecurring>(`/api/v2/cmdb/firewall.schedule/recurring/${name}`, data, params);
    return response.results;
  }

  async deleteScheduleRecurring(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall.schedule/recurring/${name}`, params);
  }

  async getSchedulesOnetime(vdom?: string): Promise<FirewallScheduleOnetime[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<FirewallScheduleOnetime[]>('/api/v2/cmdb/firewall.schedule/onetime', params);
    return response.results;
  }

  async createScheduleOnetime(data: FirewallScheduleOnetime, vdom?: string): Promise<FirewallScheduleOnetime> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<FirewallScheduleOnetime>('/api/v2/cmdb/firewall.schedule/onetime', data, params);
    return response.results;
  }

  async updateScheduleOnetime(name: string, data: Partial<FirewallScheduleOnetime>, vdom?: string): Promise<FirewallScheduleOnetime> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<FirewallScheduleOnetime>(`/api/v2/cmdb/firewall.schedule/onetime/${name}`, data, params);
    return response.results;
  }

  async deleteScheduleOnetime(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall.schedule/onetime/${name}`, params);
  }

  async getScheduleGroups(vdom?: string): Promise<FirewallScheduleGroup[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<FirewallScheduleGroup[]>('/api/v2/cmdb/firewall.schedule/group', params);
    return response.results;
  }

  async createScheduleGroup(data: FirewallScheduleGroup, vdom?: string): Promise<FirewallScheduleGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<FirewallScheduleGroup>('/api/v2/cmdb/firewall.schedule/group', data, params);
    return response.results;
  }

  async updateScheduleGroup(name: string, data: Partial<FirewallScheduleGroup>, vdom?: string): Promise<FirewallScheduleGroup> {
    const params = vdom ? { vdom } : {};
    const response = await this.put<FirewallScheduleGroup>(`/api/v2/cmdb/firewall.schedule/group/${name}`, data, params);
    return response.results;
  }

  async deleteScheduleGroup(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/firewall.schedule/group/${name}`, params);
  }

  // ==================== CERTIFICATES ====================

  async getCertificates(vdom?: string): Promise<Certificate[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<Certificate[]>('/api/v2/cmdb/vpn.certificate/local', params);
    return response.results;
  }

  async getCAs(vdom?: string): Promise<Certificate[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<Certificate[]>('/api/v2/cmdb/vpn.certificate/ca', params);
    return response.results;
  }

  async getCRLs(vdom?: string): Promise<Certificate[]> {
    const params = vdom ? { vdom } : {};
    const response = await this.get<Certificate[]>('/api/v2/cmdb/vpn.certificate/crl', params);
    return response.results;
  }

  async generateCertificate(data: Certificate, vdom?: string): Promise<Certificate> {
    const params = vdom ? { vdom } : {};
    const response = await this.post<Certificate>('/api/v2/cmdb/vpn.certificate/local', data, params);
    return response.results;
  }

  async deleteCertificate(name: string, vdom?: string): Promise<void> {
    const params = vdom ? { vdom } : {};
    await this.delete(`/api/v2/cmdb/vpn.certificate/local/${name}`, params);
  }

  // ==================== UTILITY METHODS ====================

  async checkConnectivity(): Promise<boolean> {
    try {
      await this.getSystemStatus();
      return true;
    } catch {
      return false;
    }
  }

  async getVersion(): Promise<string> {
    const status = await this.getSystemStatus();
    return status.version;
  }

  async getSerialNumber(): Promise<string> {
    const status = await this.getSystemStatus();
    return status.serial;
  }

  async getHostname(): Promise<string> {
    const status = await this.getSystemStatus();
    return status.hostname;
  }

  async getModel(): Promise<string> {
    const status = await this.getSystemStatus();
    return status.model;
  }

  async getUptime(): Promise<string> {
    const status = await this.getSystemStatus();
    return status.system_uptime;
  }
}

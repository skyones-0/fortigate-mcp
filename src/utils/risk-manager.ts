/**
 * Sistema de gestión de riesgo para operaciones FortiGate
 * Implementa niveles de riesgo y sistema de confirmation tokens
 */

import { randomBytes, createHash } from 'crypto';

// Niveles de riesgo para operaciones
export enum RiskLevel {
  LOW = 'low',       // Operaciones de solo lectura, monitoreo
  MEDIUM = 'medium', // Crear objetos, políticas, modificar
  HIGH = 'high',     // Eliminar, restore, cambios de sistema global, rollback
}

// Interfaz para información de riesgo
export interface RiskInfo {
  level: RiskLevel;
  description: string;
  requiresConfirmation: boolean;
  autoBackup: boolean;
}

// Interfaz para token de confirmación
export interface ConfirmationToken {
  token: string;
  toolName: string;
  args: Record<string, unknown>;
  riskLevel: RiskLevel;
  expiresAt: Date;
  preview?: string;
  metadata?: Record<string, unknown>;
}

// Mapa de herramientas a niveles de riesgo
const TOOL_RISK_MAP: Map<string, RiskInfo> = new Map();

// Store temporal para tokens de confirmación (en producción usar Redis o similar)
const tokenStore: Map<string, ConfirmationToken> = new Map();

// Tiempo de expiración de tokens (5 minutos)
const TOKEN_EXPIRY_MS = 5 * 60 * 1000;

/**
 * Registra el nivel de riesgo de una herramienta
 */
export function registerToolRisk(
  toolName: string,
  level: RiskLevel,
  description: string,
  options?: { autoBackup?: boolean }
): void {
  TOOL_RISK_MAP.set(toolName, {
    level,
    description,
    requiresConfirmation: level !== RiskLevel.LOW,
    autoBackup: options?.autoBackup ?? level === RiskLevel.HIGH,
  });
}

/**
 * Obtiene la información de riesgo de una herramienta
 */
export function getToolRisk(toolName: string): RiskInfo {
  return (
    TOOL_RISK_MAP.get(toolName) ?? {
      level: RiskLevel.LOW,
      description: 'Operación de solo lectura',
      requiresConfirmation: false,
      autoBackup: false,
    }
  );
}

/**
 * Verifica si una herramienta requiere confirmación
 */
export function requiresConfirmation(toolName: string): boolean {
  const risk = getToolRisk(toolName);
  return risk.requiresConfirmation;
}

/**
 * Genera un token de confirmación único
 */
export function generateConfirmationToken(): string {
  return createHash('sha256')
    .update(randomBytes(32))
    .digest('hex')
    .substring(0, 32);
}

/**
 * Crea un token de confirmación para una operación
 */
export function createConfirmationToken(
  toolName: string,
  args: Record<string, unknown>,
  preview?: string,
  metadata?: Record<string, unknown>
): ConfirmationToken {
  const riskInfo = getToolRisk(toolName);
  const token = generateConfirmationToken();
  
  const confirmationToken: ConfirmationToken = {
    token,
    toolName,
    args,
    riskLevel: riskInfo.level,
    expiresAt: new Date(Date.now() + TOKEN_EXPIRY_MS),
    preview,
    metadata,
  };

  // Almacenar token
  tokenStore.set(token, confirmationToken);

  // Limpiar tokens expirados
  cleanupExpiredTokens();

  return confirmationToken;
}

/**
 * Valida un token de confirmación
 */
export function validateConfirmationToken(
  token: string,
  toolName: string,
  args: Record<string, unknown>
): { valid: boolean; error?: string; storedToken?: ConfirmationToken } {
  const storedToken = tokenStore.get(token);

  if (!storedToken) {
    return { valid: false, error: 'Token de confirmación inválido o expirado' };
  }

  if (new Date() > storedToken.expiresAt) {
    tokenStore.delete(token);
    return { valid: false, error: 'Token de confirmación ha expirado. Por favor solicite uno nuevo.' };
  }

  if (storedToken.toolName !== toolName) {
    return { valid: false, error: 'Token de confirmación no válido para esta herramienta' };
  }

  // Verificar que los argumentos coincidan (comparación simple)
  const argsMatch = JSON.stringify(storedToken.args) === JSON.stringify(args);
  if (!argsMatch) {
    return {
      valid: false,
      error: 'Los argumentos han cambiado desde que se generó el token. Por favor genere un nuevo token.',
    };
  }

  return { valid: true, storedToken };
}

/**
 * Invalida un token de confirmación
 */
export function invalidateConfirmationToken(token: string): boolean {
  return tokenStore.delete(token);
}

/**
 * Limpia tokens expirados
 */
function cleanupExpiredTokens(): void {
  const now = new Date();
  for (const [key, token] of tokenStore.entries()) {
    if (now > token.expiresAt) {
      tokenStore.delete(key);
    }
  }
}

/**
 * Obtiene un preview de cambios para mostrar al usuario
 */
export function generateChangePreview(
  toolName: string,
  args: Record<string, unknown>
): string {
  const risk = getToolRisk(toolName);
  
  let preview = `⚠️ Operación de riesgo: ${risk.level.toUpperCase()}\n`;
  preview += `Descripción: ${risk.description}\n\n`;
  preview += `Herramienta: ${toolName}\n`;
  preview += `Argumentos:\n`;
  
  // Sanitizar argumentos (ocultar contraseñas/secretos)
  const sanitizedArgs = { ...args };
  const sensitiveFields = ['password', 'passwd', 'psksecret', 'secret', 'key', 'api_token'];
  
  for (const field of sensitiveFields) {
    if (field in sanitizedArgs) {
      sanitizedArgs[field] = '***REDACTED***';
    }
  }
  
  preview += JSON.stringify(sanitizedArgs, null, 2);
  
  if (risk.autoBackup) {
    preview += '\n\n📦 Se creará un backup automático antes de ejecutar.';
  }

  return preview;
}

/**
 * Registra herramientas predefinidas con sus niveles de riesgo
 */
export function registerPredefinedToolRisks(): void {
  // === Herramientas de Riesgo Bajo (Lectura) ===
  const lowRiskTools = [
    'list_firewall_policies', 'get_firewall_policy',
    'list_address_objects', 'get_address_object',
    'list_address_groups', 'list_service_objects',
    'list_service_groups', 'list_vips', 'list_vip_groups',
    'list_interfaces', 'get_interface', 'list_static_routes',
    'get_system_info', 'get_system_status', 'get_system_config',
    'get_system_time', 'get_system_performance', 'list_vdoms',
    'list_users', 'list_user_groups', 'list_vpn_ipsec_phase1',
    'list_vpn_ipsec_phase2', 'list_vpn_ssl_portals',
    'list_antivirus_profiles', 'list_webfilter_profiles',
    'list_ips_sensors', 'list_ssl_ssh_profiles', 'get_ha_config',
    'get_system_global', 'list_system_admins', 'list_traffic_shapers',
    'list_dhcp_servers', 'list_zones', 'get_system_performance',
    'get_vpn_status', 'get_dhcp_leases', 'get_arp_table',
    'get_routing_table', 'get_session_list',
    // Nuevas herramientas de lectura
    'list_nat46_policies', 'list_central_nat', 'list_firewall_dnats',
    'list_local_in_policies', 'list_multicast_policies', 'list_proxy_policies',
    'list_waf_profiles', 'list_emailfilter_profiles', 'list_dlp_profiles',
    'list_file_filter_profiles', 'list_voip_profiles', 'list_sctp_filter_profiles',
    'list_virtual_patch_profiles', 'get_fortiguard_status', 'get_threat_feeds',
    'list_ssl_vpn_realms', 'list_ssl_vpn_bookmarks', 'list_ipsec_p1_proposals',
    'list_ipsec_p2_proposals', 'list_ipsec_keys', 'list_dialup_tunnels',
    'list_l2tp_settings', 'list_pptp_settings', 'list_gre_tunnels',
    'list_sdwan_overlay', 'list_bgp_neighbors', 'list_bgp_networks',
    'list_ospf_areas', 'list_ospf_interfaces', 'list_ospf_neighbors',
    'list_rip_config', 'list_isis_config', 'list_policy_routes',
    'list_multicast_routing', 'list_sdwan_rules', 'list_sdwan_health_checks',
    'list_sdwan_duplicates', 'list_sdwan_zones', 'get_sdwan_history',
    'list_accprofiles', 'list_api_users', 'list_snmp_communities',
    'list_snmp_users', 'list_snmp_thresholds', 'list_auto_scripts',
    'list_stitches', 'list_triggers', 'list_actions', 'get_fortimanager_status',
    'get_forticloud_status', 'list_certificate_cas', 'list_firmware_versions',
    'list_vdom_links', 'list_vdom_properties', 'list_switch_interfaces',
    'list_switch_vlans', 'list_switch_stp', 'list_mclag', 'list_wl_ap_profiles',
    'list_wl_aps', 'list_ssids', 'list_wl_clients', 'list_ble_profiles',
    'list_link_monitors', 'get_link_monitor_results', 'list_virtual_switches',
    'list_virtual_wire_pairs', 'list_vxlan_interfaces', 'list_ipv6_policies',
    'list_ipv6_addresses', 'list_ztna_gateways', 'list_ztna_proxies',
    'list_ztna_tags', 'list_saml_servers', 'list_saml_users', 'list_saml_groups',
    'list_fortitokens', 'list_fsso_agents', 'list_fsso_groups', 'list_fsso_pollers',
    'list_log_settings_detailed', 'list_log_filters', 'list_faz_settings',
    'list_syslog_servers', 'list_cef_settings', 'list_report_settings',
    'get_report_status', 'get_capture_status', 'get_system_health',
    'get_interface_stats', 'get_cpu_history', 'get_memory_history',
    'get_session_stats', 'get_anomaly_stats', 'get_ip_reputation',
    'list_backups', 'list_snapshots', 'get_change_history',
  ];

  lowRiskTools.forEach(tool => {
    registerToolRisk(tool, RiskLevel.LOW, 'Operación de solo lectura');
  });

  // === Herramientas de Riesgo Medio (Crear/Modificar) ===
  const mediumRiskTools = [
    { name: 'create_firewall_policy', desc: 'Crear política de firewall' },
    { name: 'update_firewall_policy', desc: 'Modificar política de firewall' },
    { name: 'move_firewall_policy', desc: 'Reordenar políticas de firewall' },
    { name: 'create_address_object', desc: 'Crear objeto de dirección' },
    { name: 'update_address_object', desc: 'Modificar objeto de dirección' },
    { name: 'create_address_group', desc: 'Crear grupo de direcciones' },
    { name: 'update_address_group', desc: 'Modificar grupo de direcciones' },
    { name: 'create_service_object', desc: 'Crear objeto de servicio' },
    { name: 'update_service_object', desc: 'Modificar objeto de servicio' },
    { name: 'create_service_group', desc: 'Crear grupo de servicios' },
    { name: 'create_vip', desc: 'Crear Virtual IP' },
    { name: 'update_vip', desc: 'Modificar Virtual IP' },
    { name: 'create_vip_group', desc: 'Crear grupo de VIPs' },
    { name: 'update_vip_group', desc: 'Modificar grupo de VIPs' },
    { name: 'update_interface', desc: 'Modificar interfaz' },
    { name: 'create_static_route', desc: 'Crear ruta estática' },
    { name: 'update_static_route', desc: 'Modificar ruta estática' },
    { name: 'create_vdom', desc: 'Crear VDOM' },
    { name: 'create_user', desc: 'Crear usuario local' },
    { name: 'update_user', desc: 'Modificar usuario' },
    { name: 'create_user_group', desc: 'Crear grupo de usuarios' },
    { name: 'create_vpn_ipsec_phase1', desc: 'Crear túnel VPN IPsec Phase 1' },
    { name: 'update_vpn_ipsec_phase1', desc: 'Modificar VPN IPsec Phase 1' },
    { name: 'create_vpn_ipsec_phase2', desc: 'Crear VPN IPsec Phase 2' },
    { name: 'update_vpn_ipsec_phase2', desc: 'Modificar VPN IPsec Phase 2' },
    { name: 'create_antivirus_profile', desc: 'Crear perfil antivirus' },
    { name: 'update_antivirus_profile', desc: 'Modificar perfil antivirus' },
    { name: 'create_webfilter_profile', desc: 'Crear perfil web filter' },
    { name: 'update_webfilter_profile', desc: 'Modificar perfil web filter' },
    { name: 'create_ips_sensor', desc: 'Crear sensor IPS' },
    { name: 'update_ips_sensor', desc: 'Modificar sensor IPS' },
    { name: 'create_ssl_ssh_profile', desc: 'Crear perfil SSL/SSH' },
    { name: 'update_ssl_ssh_profile', desc: 'Modificar perfil SSL/SSH' },
    { name: 'update_ha_config', desc: 'Modificar configuración HA' },
    { name: 'update_system_global', desc: 'Modificar configuración global' },
    { name: 'create_system_admin', desc: 'Crear administrador' },
    { name: 'update_system_admin', desc: 'Modificar administrador' },
    { name: 'create_traffic_shaper', desc: 'Crear traffic shaper' },
    { name: 'create_dhcp_server', desc: 'Crear servidor DHCP' },
    { name: 'update_dhcp_server', desc: 'Modificar servidor DHCP' },
    { name: 'create_zone', desc: 'Crear zona' },
    { name: 'update_zone', desc: 'Modificar zona' },
    { name: 'backup_config', desc: 'Crear backup de configuración' },
    { name: 'execute_cli_command', desc: 'Ejecutar comando CLI' },
    { name: 'create_snapshot', desc: 'Crear snapshot manual' },
    // Nuevas herramientas medium
    { name: 'create_nat46_policy', desc: 'Crear política NAT46' },
    { name: 'create_central_nat', desc: 'Crear entrada Central NAT' },
    { name: 'create_firewall_dnat', desc: 'Crear regla DNAT' },
    { name: 'create_local_in_policy', desc: 'Crear política Local-In' },
    { name: 'create_multicast_policy', desc: 'Crear política multicast' },
    { name: 'create_proxy_policy', desc: 'Crear política proxy' },
    { name: 'create_waf_profile', desc: 'Crear perfil WAF' },
    { name: 'create_emailfilter_profile', desc: 'Crear perfil email filter' },
    { name: 'create_dlp_profile', desc: 'Crear perfil DLP' },
    { name: 'create_file_filter_profile', desc: 'Crear perfil file filter' },
    { name: 'create_voip_profile', desc: 'Crear perfil VoIP' },
    { name: 'create_sctp_filter_profile', desc: 'Crear perfil SCTP filter' },
    { name: 'create_virtual_patch_profile', desc: 'Crear perfil virtual patch' },
    { name: 'update_fortiguard_config', desc: 'Actualizar FortiGuard' },
    { name: 'create_ssl_vpn_realm', desc: 'Crear SSL VPN realm' },
    { name: 'create_ssl_vpn_bookmark', desc: 'Crear SSL VPN bookmark' },
    { name: 'create_ipsec_p1_proposal', desc: 'Crear proposal IPsec P1' },
    { name: 'create_ipsec_p2_proposal', desc: 'Crear proposal IPsec P2' },
    { name: 'manage_ipsec_keys', desc: 'Gestionar claves IPsec' },
    { name: 'create_dialup_tunnel', desc: 'Crear túnel dialup' },
    { name: 'update_l2tp_settings', desc: 'Actualizar L2TP' },
    { name: 'create_gre_tunnel', desc: 'Crear túnel GRE' },
    { name: 'configure_sdwan_vpn', desc: 'Configurar SD-WAN VPN' },
    { name: 'create_bgp_neighbor', desc: 'Crear vecino BGP' },
    { name: 'create_bgp_network', desc: 'Crear red BGP' },
    { name: 'create_ospf_area', desc: 'Crear área OSPF' },
    { name: 'configure_ospf_interface', desc: 'Configurar interfaz OSPF' },
    { name: 'configure_rip', desc: 'Configurar RIP' },
    { name: 'configure_isis', desc: 'Configurar IS-IS' },
    { name: 'create_policy_route', desc: 'Crear policy route' },
    { name: 'configure_multicast', desc: 'Configurar multicast' },
    { name: 'create_sdwan_rule', desc: 'Crear regla SD-WAN' },
    { name: 'create_sdwan_health_check', desc: 'Crear health check SD-WAN' },
    { name: 'create_sdwan_zone', desc: 'Crear zona SD-WAN' },
    { name: 'create_accprofile', desc: 'Crear perfil de acceso' },
    { name: 'create_api_user', desc: 'Crear usuario API' },
    { name: 'update_api_user', desc: 'Actualizar usuario API' },
    { name: 'regenerate_api_key', desc: 'Regenerar API key' },
    { name: 'create_snmp_community', desc: 'Crear comunidad SNMP' },
    { name: 'create_snmp_user', desc: 'Crear usuario SNMP' },
    { name: 'configure_snmp_threshold', desc: 'Configurar umbral SNMP' },
    { name: 'create_auto_script', desc: 'Crear script de automatización' },
    { name: 'execute_auto_script', desc: 'Ejecutar script' },
    { name: 'create_stitch', desc: 'Crear automation stitch' },
    { name: 'create_trigger', desc: 'Crear trigger' },
    { name: 'create_action', desc: 'Crear action' },
    { name: 'configure_fortimanager', desc: 'Configurar FortiManager' },
    { name: 'configure_forticloud', desc: 'Configurar FortiCloud' },
    { name: 'import_ca', desc: 'Importar CA' },
    { name: 'generate_csr', desc: 'Generar CSR' },
    { name: 'import_certificate', desc: 'Importar certificado' },
    { name: 'renew_certificate', desc: 'Renovar certificado' },
    { name: 'upload_firmware', desc: 'Subir firmware' },
    { name: 'verify_firmware', desc: 'Verificar firmware' },
    { name: 'schedule_upgrade', desc: 'Programar upgrade' },
    { name: 'create_vdom_link', desc: 'Crear VDOM link' },
    { name: 'configure_vdom_property', desc: 'Configurar propiedad VDOM' },
    { name: 'configure_switch_port', desc: 'Configurar puerto switch' },
    { name: 'create_switch_vlan', desc: 'Crear VLAN switch' },
    { name: 'configure_switch_stp', desc: 'Configurar STP' },
    { name: 'configure_mclag', desc: 'Configurar MCLAG' },
    { name: 'create_wl_ap_profile', desc: 'Crear perfil AP' },
    { name: 'manage_wl_ap', desc: 'Gestionar AP' },
    { name: 'create_ssid', desc: 'Crear SSID' },
    { name: 'create_link_monitor', desc: 'Crear monitor de enlace' },
    { name: 'create_virtual_switch', desc: 'Crear virtual switch' },
    { name: 'create_virtual_wire_pair', desc: 'Crear virtual wire pair' },
    { name: 'create_vxlan_interface', desc: 'Crear interfaz VXLAN' },
    { name: 'create_ipv6_policy', desc: 'Crear política IPv6' },
    { name: 'configure_ipv6', desc: 'Configurar IPv6' },
    { name: 'create_ztna_gateway', desc: 'Crear ZTNA gateway' },
    { name: 'create_ztna_proxy', desc: 'Crear ZTNA proxy' },
    { name: 'create_ztna_tag', desc: 'Crear ZTNA tag' },
    { name: 'create_saml_server', desc: 'Crear servidor SAML' },
    { name: 'provision_fortitoken', desc: 'Provisionar FortiToken' },
    { name: 'sync_fortitoken', desc: 'Sincronizar FortiToken' },
    { name: 'configure_fsso_agent', desc: 'Configurar agente FSSO' },
    { name: 'configure_log_settings', desc: 'Configurar logs' },
    { name: 'create_log_filter', desc: 'Crear filtro de log' },
    { name: 'configure_faz', desc: 'Configurar FortiAnalyzer' },
    { name: 'test_faz_connectivity', desc: 'Probar conectividad FAZ' },
    { name: 'create_syslog_server', desc: 'Crear servidor syslog' },
    { name: 'configure_report', desc: 'Configurar reporte' },
    { name: 'run_report', desc: 'Ejecutar reporte' },
    { name: 'start_packet_capture', desc: 'Iniciar captura de paquetes' },
    { name: 'stop_packet_capture', desc: 'Detener captura' },
    { name: 'ping', desc: 'Ping desde FortiGate' },
    { name: 'traceroute', desc: 'Traceroute' },
    { name: 'nslookup', desc: 'DNS lookup' },
    { name: 'execute_diagnostics', desc: 'Ejecutar diagnósticos' },
    { name: 'submit_false_positive', desc: 'Reportar falso positivo' },
  ];

  mediumRiskTools.forEach(({ name, desc }) => {
    registerToolRisk(name, RiskLevel.MEDIUM, desc, { autoBackup: false });
  });

  // === Herramientas de Riesgo Alto (Eliminar/Restore/Rollback) ===
  const highRiskTools = [
    { name: 'delete_firewall_policy', desc: 'Eliminar política de firewall' },
    { name: 'delete_address_object', desc: 'Eliminar objeto de dirección' },
    { name: 'delete_address_group', desc: 'Eliminar grupo de direcciones' },
    { name: 'delete_service_object', desc: 'Eliminar objeto de servicio' },
    { name: 'delete_service_group', desc: 'Eliminar grupo de servicios' },
    { name: 'delete_vip', desc: 'Eliminar Virtual IP' },
    { name: 'delete_vip_group', desc: 'Eliminar grupo de VIPs' },
    { name: 'delete_static_route', desc: 'Eliminar ruta estática' },
    { name: 'delete_vdom', desc: 'Eliminar VDOM' },
    { name: 'delete_user', desc: 'Eliminar usuario' },
    { name: 'delete_user_group', desc: 'Eliminar grupo de usuarios' },
    { name: 'delete_vpn_ipsec_phase1', desc: 'Eliminar túnel VPN IPsec' },
    { name: 'delete_vpn_ipsec_phase2', desc: 'Eliminar Phase 2 IPsec' },
    { name: 'delete_antivirus_profile', desc: 'Eliminar perfil antivirus' },
    { name: 'delete_webfilter_profile', desc: 'Eliminar perfil web filter' },
    { name: 'delete_ips_sensor', desc: 'Eliminar sensor IPS' },
    { name: 'delete_ssl_ssh_profile', desc: 'Eliminar perfil SSL/SSH' },
    { name: 'delete_system_admin', desc: 'Eliminar administrador' },
    { name: 'delete_traffic_shaper', desc: 'Eliminar traffic shaper' },
    { name: 'delete_dhcp_server', desc: 'Eliminar servidor DHCP' },
    { name: 'delete_zone', desc: 'Eliminar zona' },
    { name: 'restore_config', desc: 'Restaurar configuración desde backup' },
    { name: 'reboot', desc: 'Reiniciar FortiGate' },
    { name: 'shutdown', desc: 'Apagar FortiGate' },
    { name: 'upgrade_firmware', desc: 'Actualizar firmware' },
    // Nuevas herramientas high risk
    { name: 'delete_nat46_policy', desc: 'Eliminar política NAT46' },
    { name: 'delete_central_nat', desc: 'Eliminar entrada Central NAT' },
    { name: 'delete_firewall_dnat', desc: 'Eliminar regla DNAT' },
    { name: 'delete_local_in_policy', desc: 'Eliminar política Local-In' },
    { name: 'delete_multicast_policy', desc: 'Eliminar política multicast' },
    { name: 'delete_proxy_policy', desc: 'Eliminar política proxy' },
    { name: 'delete_waf_profile', desc: 'Eliminar perfil WAF' },
    { name: 'delete_emailfilter_profile', desc: 'Eliminar perfil email filter' },
    { name: 'delete_dlp_profile', desc: 'Eliminar perfil DLP' },
    { name: 'delete_file_filter_profile', desc: 'Eliminar perfil file filter' },
    { name: 'delete_voip_profile', desc: 'Eliminar perfil VoIP' },
    { name: 'delete_sctp_filter_profile', desc: 'Eliminar perfil SCTP filter' },
    { name: 'delete_virtual_patch_profile', desc: 'Eliminar perfil virtual patch' },
    { name: 'delete_ssl_vpn_realm', desc: 'Eliminar SSL VPN realm' },
    { name: 'delete_ssl_vpn_bookmark', desc: 'Eliminar SSL VPN bookmark' },
    { name: 'delete_ipsec_p1_proposal', desc: 'Eliminar proposal IPsec P1' },
    { name: 'delete_ipsec_p2_proposal', desc: 'Eliminar proposal IPsec P2' },
    { name: 'delete_dialup_tunnel', desc: 'Eliminar túnel dialup' },
    { name: 'delete_gre_tunnel', desc: 'Eliminar túnel GRE' },
    { name: 'delete_bgp_neighbor', desc: 'Eliminar vecino BGP' },
    { name: 'delete_bgp_network', desc: 'Eliminar red BGP' },
    { name: 'delete_ospf_area', desc: 'Eliminar área OSPF' },
    { name: 'delete_policy_route', desc: 'Eliminar policy route' },
    { name: 'delete_sdwan_rule', desc: 'Eliminar regla SD-WAN' },
    { name: 'delete_sdwan_health_check', desc: 'Eliminar health check SD-WAN' },
    { name: 'delete_sdwan_zone', desc: 'Eliminar zona SD-WAN' },
    { name: 'delete_api_user', desc: 'Eliminar usuario API' },
    { name: 'delete_snmp_community', desc: 'Eliminar comunidad SNMP' },
    { name: 'delete_snmp_user', desc: 'Eliminar usuario SNMP' },
    { name: 'delete_auto_script', desc: 'Eliminar script' },
    { name: 'delete_stitch', desc: 'Eliminar stitch' },
    { name: 'delete_trigger', desc: 'Eliminar trigger' },
    { name: 'delete_action', desc: 'Eliminar action' },
    { name: 'delete_certificate', desc: 'Eliminar certificado' },
    { name: 'delete_vdom_link', desc: 'Eliminar VDOM link' },
    { name: 'delete_switch_vlan', desc: 'Eliminar VLAN switch' },
    { name: 'delete_ssid', desc: 'Eliminar SSID' },
    { name: 'delete_link_monitor', desc: 'Eliminar monitor de enlace' },
    { name: 'delete_virtual_switch', desc: 'Eliminar virtual switch' },
    { name: 'delete_virtual_wire_pair', desc: 'Eliminar virtual wire pair' },
    { name: 'delete_vxlan_interface', desc: 'Eliminar interfaz VXLAN' },
    { name: 'delete_ipv6_policy', desc: 'Eliminar política IPv6' },
    { name: 'delete_ztna_gateway', desc: 'Eliminar ZTNA gateway' },
    { name: 'delete_ztna_proxy', desc: 'Eliminar ZTNA proxy' },
    { name: 'delete_ztna_tag', desc: 'Eliminar ZTNA tag' },
    { name: 'delete_saml_server', desc: 'Eliminar servidor SAML' },
    { name: 'delete_syslog_server', desc: 'Eliminar servidor syslog' },
    { name: 'delete_backup', desc: 'Eliminar backup' },
    { name: 'delete_snapshot', desc: 'Eliminar snapshot' },
    { name: 'rollback_to_snapshot', desc: 'Rollback a snapshot' },
    { name: 'discard_changes', desc: 'Descartar cambios no guardados' },
    { name: 'clear_all_sessions', desc: 'Limpiar todas las sesiones' },
    { name: 'clear_session', desc: 'Limpiar sesión específica' },
  ];

  highRiskTools.forEach(({ name, desc }) => {
    registerToolRisk(name, RiskLevel.HIGH, desc, { autoBackup: true });
  });
}

// Inicializar registros al cargar
registerPredefinedToolRisks();

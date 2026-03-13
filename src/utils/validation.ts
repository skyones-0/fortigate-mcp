/**
 * Utilidades de validación con Zod para FortiGate MCP Server
 */

import { z } from 'zod';

// Esquema de configuración de conexión
export const FortiGateConfigSchema = z.object({
  host: z.string().min(1, 'Host es requerido'),
  apiToken: z.string().min(1, 'API Token es requerido'),
  port: z.number().int().min(1).max(65535).optional(),
  https: z.boolean().optional(),
  verifySsl: z.boolean().optional(),
  timeout: z.number().int().min(1000).optional(),
});

// Esquemas para Firewall Policies
export const CreateFirewallPolicySchema = z.object({
  name: z.string().optional(),
  srcintf: z.union([z.string(), z.array(z.string())]),
  dstintf: z.union([z.string(), z.array(z.string())]),
  srcaddr: z.union([z.string(), z.array(z.string())]),
  dstaddr: z.union([z.string(), z.array(z.string())]),
  action: z.enum(['accept', 'deny', 'ipsec', 'ssl-vpn']),
  schedule: z.string().optional(),
  service: z.union([z.string(), z.array(z.string())]),
  logtraffic: z.enum(['all', 'utm', 'disable']).optional(),
  nat: z.enum(['enable', 'disable']).optional(),
  status: z.enum(['enable', 'disable']).optional(),
  comments: z.string().optional(),
  groups: z.array(z.string()).optional(),
  users: z.array(z.string()).optional(),
  ips_sensor: z.string().optional(),
  webfilter_profile: z.string().optional(),
  dnsfilter_profile: z.string().optional(),
  av_profile: z.string().optional(),
  app_profile: z.string().optional(),
  ssl_ssh_profile: z.string().optional(),
  waf_profile: z.string().optional(),
  profile_protocol_options: z.string().optional(),
  profile_group: z.string().optional(),
  poolname: z.array(z.string()).optional(),
  capture_packet: z.enum(['enable', 'disable']).optional(),
  ippool: z.enum(['enable', 'disable']).optional(),
  fixedport: z.enum(['enable', 'disable']).optional(),
  traffic_shaper: z.string().optional(),
  traffic_shaper_reverse: z.string().optional(),
  per_ip_shaper: z.string().optional(),
  utm_status: z.enum(['enable', 'disable']).optional(),
});

export const UpdateFirewallPolicySchema = CreateFirewallPolicySchema.partial();

// Esquemas para Address Objects
export const CreateAddressObjectSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  subnet: z.string().optional(),
  type: z.enum(['ipmask', 'iprange', 'fqdn', 'geography', 'wildcard', 'wildcard-fqdn', 'mac', 'dynamic', 'interface-subnet']).optional(),
  start_ip: z.string().optional(),
  end_ip: z.string().optional(),
  fqdn: z.string().optional(),
  country: z.string().optional(),
  wildcard: z.string().optional(),
  macaddr: z.array(z.string()).optional(),
  interface: z.string().optional(),
  comment: z.string().optional(),
  associated_interface: z.string().optional(),
  color: z.number().optional(),
  allow_routing: z.enum(['enable', 'disable']).optional(),
});

export const UpdateAddressObjectSchema = CreateAddressObjectSchema.partial().omit({ name: true });

// Esquemas para Address Groups
export const CreateAddressGroupSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  member: z.union([z.string(), z.array(z.string())]),
  comment: z.string().optional(),
  color: z.number().optional(),
});

export const UpdateAddressGroupSchema = CreateAddressGroupSchema.partial().omit({ name: true });

// Esquemas para Service Objects
export const CreateServiceObjectSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  category: z.string().optional(),
  protocol: z.enum(['TCP', 'UDP', 'SCTP', 'ICMP', 'ICMP6', 'IP']).optional(),
  'tcp-portrange': z.string().optional(),
  'udp-portrange': z.string().optional(),
  'sctp-portrange': z.string().optional(),
  icmptype: z.number().optional(),
  icmpcode: z.number().optional(),
  protocol_number: z.number().optional(),
  comment: z.string().optional(),
  color: z.number().optional(),
});

export const UpdateServiceObjectSchema = CreateServiceObjectSchema.partial().omit({ name: true });

// Esquemas para Service Groups
export const CreateServiceGroupSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  member: z.union([z.string(), z.array(z.string())]),
  comment: z.string().optional(),
  color: z.number().optional(),
});

export const UpdateServiceGroupSchema = CreateServiceGroupSchema.partial().omit({ name: true });

// Esquemas para VIPs (Virtual IPs)
export const CreateVIPSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  extip: z.string(),
  mappedip: z.string(),
  extintf: z.string(),
  portforward: z.enum(['enable', 'disable']).optional(),
  protocol: z.enum(['tcp', 'udp', 'sctp']).optional(),
  extport: z.string().optional(),
  mappedport: z.string().optional(),
  comment: z.string().optional(),
  color: z.number().optional(),
});

export const UpdateVIPSchema = CreateVIPSchema.partial().omit({ name: true });

// Esquemas para VIP Groups
export const CreateVIPGroupSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  member: z.union([z.string(), z.array(z.string())]),
  interface: z.string().optional(),
  color: z.number().optional(),
  comments: z.string().optional(),
});

export const UpdateVIPGroupSchema = CreateVIPGroupSchema.partial().omit({ name: true });

// Esquemas para Interfaces
export const CreateInterfaceSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  alias: z.string().optional(),
  ip: z.string().optional(),
  allowaccess: z.string().optional(),
  description: z.string().optional(),
  status: z.enum(['up', 'down']).optional(),
  role: z.enum(['lan', 'wan', 'dmz', 'undefined']).optional(),
  type: z.enum(['physical', 'vlan', 'loopback', 'tunnel', 'aggregate', 'redundant', 'zone']).optional(),
  mode: z.enum(['static', 'dhcp', 'pppoe']).optional(),
  vlanid: z.number().optional(),
  interface: z.string().optional(),
  vdom: z.string().optional(),
});

export const UpdateInterfaceSchema = CreateInterfaceSchema.partial().omit({ name: true });

// Esquemas para Static Routes
export const CreateStaticRouteSchema = z.object({
  seq_num: z.number().optional(),
  dst: z.string(),
  gateway: z.string(),
  device: z.string().optional(),
  distance: z.number().optional(),
  priority: z.number().optional(),
  comment: z.string().optional(),
  status: z.enum(['enable', 'disable']).optional(),
  blackhole: z.enum(['enable', 'disable']).optional(),
});

export const UpdateStaticRouteSchema = CreateStaticRouteSchema.partial();

// Esquemas para Users
export const CreateUserLocalSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  status: z.enum(['enable', 'disable']).optional(),
  type: z.enum(['password', 'radius', 'tacacs-plus', 'ldap', 'fortitoken', 'email', 'sms', 'certificate', 'sso']).optional(),
  passwd: z.string().optional(),
  'two-factor': z.enum(['disable', 'fortitoken', 'email', 'sms']).optional(),
  email_to: z.string().optional(),
  sms_server: z.enum(['fortiguard', 'custom']).optional(),
  sms_custom_server: z.string().optional(),
  passwd_time: z.string().optional(),
  passwd_policy: z.string().optional(),
  comment: z.string().optional(),
});

export const UpdateUserLocalSchema = CreateUserLocalSchema.partial().omit({ name: true });

// Esquemas para User Groups
export const CreateUserGroupSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  member: z.array(z.string()).optional(),
  'match-type': z.enum(['or', 'and']).optional(),
  'user-group-type': z.enum(['firewall', 'fsso', 'rsso', 'guest']).optional(),
  comment: z.string().optional(),
});

export const UpdateUserGroupSchema = CreateUserGroupSchema.partial().omit({ name: true });

// Esquemas para VPN IPsec Phase 1
export const CreateVPNIPsecPhase1Schema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  interface: z.string(),
  ike_version: z.enum(['1', '2']).optional(),
  peertype: z.enum(['any', 'one', 'dialup', 'peer', 'peergrp']).optional(),
  proposal: z.array(z.string()).optional(),
  local_gw: z.string().optional(),
  remote_gw: z.string().optional(),
  psksecret: z.string().optional(),
  dpd: z.enum(['disable', 'on-idle', 'on-demand']).optional(),
  dhgrp: z.array(z.string()).optional(),
  keylifeseconds: z.number().optional(),
  nattraversal: z.enum(['enable', 'disable', 'forced']).optional(),
  comment: z.string().optional(),
});

export const UpdateVPNIPsecPhase1Schema = CreateVPNIPsecPhase1Schema.partial().omit({ name: true });

// Esquemas para VPN IPsec Phase 2
export const CreateVPNIPsecPhase2Schema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  phase1name: z.string(),
  proposal: z.array(z.string()).optional(),
  dhgrp: z.array(z.string()).optional(),
  keylifeseconds: z.number().optional(),
  keylifekbs: z.number().optional(),
  src_subnet: z.string().optional(),
  dst_subnet: z.string().optional(),
  src_name: z.string().optional(),
  dst_name: z.string().optional(),
  auto_negotiate: z.enum(['enable', 'disable']).optional(),
  comments: z.string().optional(),
});

export const UpdateVPNIPsecPhase2Schema = CreateVPNIPsecPhase2Schema.partial().omit({ name: true });

// Esquemas para Antivirus Profiles
export const CreateAntivirusProfileSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  'http-scan': z.enum(['enable', 'disable']).optional(),
  'ftp-scan': z.enum(['enable', 'disable']).optional(),
  'imap-scan': z.enum(['enable', 'disable']).optional(),
  'pop3-scan': z.enum(['enable', 'disable']).optional(),
  'smtp-scan': z.enum(['enable', 'disable']).optional(),
  'mapi-scan': z.enum(['enable', 'disable']).optional(),
  'nntp-scan': z.enum(['enable', 'disable']).optional(),
  'cifs-scan': z.enum(['enable', 'disable']).optional(),
  analytics_max_upload: z.number().optional(),
  analytics_db: z.enum(['enable', 'disable']).optional(),
  analytics_bl: z.enum(['enable', 'disable']).optional(),
  analytics_wl: z.enum(['enable', 'disable']).optional(),
});

export const UpdateAntivirusProfileSchema = CreateAntivirusProfileSchema.partial().omit({ name: true });

// Esquemas para Web Filter Profiles
export const CreateWebFilterProfileSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  feature_set: z.enum(['flow', 'proxy']).optional(),
  inspection_mode: z.enum(['proxy', 'flow-based']).optional(),
  options: z.string().optional(),
  override: z.array(z.string()).optional(),
  'web-filter-cookie-removal': z.enum(['enable', 'disable']).optional(),
  'web-filter-activex-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-java-applet-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-jscript-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-vbs-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-unknown-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-cookie-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-applet-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-url-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-invalid-domain-log': z.enum(['enable', 'disable']).optional(),
  'web-filter-keyword-match': z.string().optional(),
  'web-filter-content-header-list': z.string().optional(),
});

export const UpdateWebFilterProfileSchema = CreateWebFilterProfileSchema.partial().omit({ name: true });

// Esquemas para DNS Filter Profiles
export const CreateDNSFilterProfileSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  'dns-filter-policy': z.string().optional(),
  'safe-search': z.enum(['disable', 'enforce']).optional(),
  'youtube-restrict': z.enum(['strict', 'moderate']).optional(),
  'log-all-domain': z.enum(['enable', 'disable']).optional(),
  'sdns-server': z.string().optional(),
  'sdns-domain-log': z.enum(['enable', 'disable']).optional(),
  'sdns-ftgd-err-log': z.enum(['enable', 'disable']).optional(),
  'block-action': z.enum(['block', 'redirect']).optional(),
  'redirect-portal': z.string().optional(),
  'redirect-portal6': z.string().optional(),
});

export const UpdateDNSFilterProfileSchema = CreateDNSFilterProfileSchema.partial().omit({ name: true });

// Esquemas para Application Control Profiles
export const CreateApplicationControlProfileSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  'app-replacemsg': z.enum(['enable', 'disable']).optional(),
  'other-application-action': z.enum(['pass', 'block', 'monitor']).optional(),
  'unknown-application-action': z.enum(['pass', 'block', 'monitor']).optional(),
  'risk-level-action': z.string().optional(),
  'technology-filter': z.string().optional(),
  'vendor-filter': z.string().optional(),
  'behavior-filter': z.string().optional(),
  'popularity-filter': z.string().optional(),
  'protocols-filter': z.string().optional(),
  'os-filter': z.string().optional(),
});

export const UpdateApplicationControlProfileSchema = CreateApplicationControlProfileSchema.partial().omit({ name: true });

// Esquemas para IPS Sensors
export const CreateIPSSensorSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  'ips-filter': z.string().optional(),
  'log-packet': z.enum(['enable', 'disable']).optional(),
  'packet-log-history': z.number().optional(),
  'packet-log-memory': z.number().optional(),
  'packet-log-post-attack': z.number().optional(),
  'scan-botnet-connections': z.enum(['disable', 'block', 'monitor']).optional(),
});

export const UpdateIPSSensorSchema = CreateIPSSensorSchema.partial().omit({ name: true });

// Esquemas para SSL/SSH Profiles
export const CreateSSLSSHProfileSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  comment: z.string().optional(),
  ssl: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  https: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  ftps: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  imaps: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  pop3s: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  smtps: z.enum(['disable', 'certificate-inspection', 'deep-inspection']).optional(),
  ssh: z.enum(['disable', 'deep-inspection']).optional(),
  'ssl-anomalies-log': z.enum(['enable', 'disable']).optional(),
  'ssl-exemptions-log': z.enum(['enable', 'disable']).optional(),
  'ssl-exemption': z.array(z.string()).optional(),
  'ssl-exemption-ip': z.array(z.string()).optional(),
  'use-ssl-server': z.enum(['enable', 'disable']).optional(),
  'ssl-server': z.array(z.string()).optional(),
});

export const UpdateSSLSSHProfileSchema = CreateSSLSSHProfileSchema.partial().omit({ name: true });

// Esquemas para Traffic Shapers
export const CreateTrafficShaperSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  'guaranteed-bandwidth': z.number().optional(),
  'maximum-bandwidth': z.number().optional(),
  'bandwidth-unit': z.enum(['kbps', 'mbps', 'gbps']).optional(),
  priority: z.enum(['low', 'medium', 'high', 'critical', 'top']).optional(),
  'dscp-marking': z.string().optional(),
  'per-policy': z.enum(['enable', 'disable']).optional(),
  comment: z.string().optional(),
});

export const UpdateTrafficShaperSchema = CreateTrafficShaperSchema.partial().omit({ name: true });

// Esquemas para Per-IP Traffic Shapers
export const CreateTrafficShaperPerIPSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  'max-concurrent-session': z.number().optional(),
  'rate-mode': z.enum(['periodical', 'continuous']).optional(),
  'bandwidth-unit': z.enum(['kbps', 'mbps', 'gbps']).optional(),
  'max-bandwidth': z.number().optional(),
  'max-bandwidth-display': z.string().optional(),
  'diffservcode': z.string().optional(),
  comment: z.string().optional(),
});

export const UpdateTrafficShaperPerIPSchema = CreateTrafficShaperPerIPSchema.partial().omit({ name: true });

// Esquemas para Schedules
export const CreateScheduleRecurringSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  day: z.enum(['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'none']).optional(),
  start: z.string().optional(),
  end: z.string().optional(),
  color: z.number().optional(),
});

export const UpdateScheduleRecurringSchema = CreateScheduleRecurringSchema.partial().omit({ name: true });

export const CreateScheduleOnetimeSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  start: z.string(),
  end: z.string(),
  color: z.number().optional(),
});

export const UpdateScheduleOnetimeSchema = CreateScheduleOnetimeSchema.partial().omit({ name: true });

// Esquemas para Zones
export const CreateZoneSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  interface: z.array(z.string()).optional(),
  description: z.string().optional(),
  intrazone: z.enum(['allow', 'deny']).optional(),
});

export const UpdateZoneSchema = CreateZoneSchema.partial().omit({ name: true });

// Esquemas para System Global
export const UpdateSystemGlobalSchema = z.object({
  hostname: z.string().optional(),
  alias: z.string().optional(),
  'timezone-option': z.string().optional(),
  timezone: z.string().optional(),
  'gui-ipv6': z.enum(['enable', 'disable']).optional(),
  'gui-certificates': z.enum(['enable', 'disable']).optional(),
  'gui-custom-language': z.enum(['enable', 'disable']).optional(),
  'gui-display-hostname': z.enum(['enable', 'disable']).optional(),
  'gui-theme': z.enum(['blue', 'green', 'red', 'melongene', 'mariner']).optional(),
  admintimeout: z.number().optional(),
  'admin-https-ssl-versions': z.string().optional(),
  'admin-https-redirect': z.enum(['enable', 'disable']).optional(),
  'admin-sport': z.number().optional(),
  'admin-port': z.number().optional(),
  'admin-ssh-port': z.number().optional(),
  'admin-telnet-port': z.number().optional(),
  'admin-maintainer': z.enum(['enable', 'disable']).optional(),
  'admin-scp': z.enum(['enable', 'disable']).optional(),
  'cfg-save': z.enum(['automatic', 'manual', 'revert']).optional(),
  language: z.enum(['english', 'simch', 'japanese', 'korean', 'spanish', 'trach']).optional(),
  'gui-date-format': z.enum(['yyyy/mm/dd', 'dd/mm/yyyy', 'mm/dd/yyyy', 'yyyy-mm-dd', 'dd-mm-yyyy', 'mm-dd-yyyy']).optional(),
  'gui-line-dashboard': z.enum(['enable', 'disable']).optional(),
  'gui-wireless-opensecurity': z.enum(['enable', 'disable']).optional(),
  'gui-cdn-usage': z.enum(['enable', 'disable']).optional(),
  'gui-auto-upgrade-setup-warning': z.enum(['enable', 'disable']).optional(),
  'gui-forticare-registration-setup-warning': z.enum(['enable', 'disable']).optional(),
  'gui-firmware-upgrade-warning': z.enum(['enable', 'disable']).optional(),
});

// Esquemas para System Admin
export const CreateSystemAdminSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  password: z.string().optional(),
  'peer-auth': z.enum(['enable', 'disable']).optional(),
  'peer-group': z.string().optional(),
  trusthost1: z.string().optional(),
  trusthost2: z.string().optional(),
  trusthost3: z.string().optional(),
  trusthost4: z.string().optional(),
  trusthost5: z.string().optional(),
  trusthost6: z.string().optional(),
  trusthost7: z.string().optional(),
  trusthost8: z.string().optional(),
  trusthost9: z.string().optional(),
  trusthost10: z.string().optional(),
  ip6_trusthost1: z.string().optional(),
  ip6_trusthost2: z.string().optional(),
  ip6_trusthost3: z.string().optional(),
  ip6_trusthost4: z.string().optional(),
  ip6_trusthost5: z.string().optional(),
  ip6_trusthost6: z.string().optional(),
  ip6_trusthost7: z.string().optional(),
  ip6_trusthost8: z.string().optional(),
  ip6_trusthost9: z.string().optional(),
  ip6_trusthost10: z.string().optional(),
  accprofile: z.string().optional(),
  'allow-remove-admin-session': z.enum(['enable', 'disable']).optional(),
  comments: z.string().optional(),
  'vdom-admin': z.enum(['enable', 'disable']).optional(),
  vdom: z.array(z.string()).optional(),
  'wildcard': z.enum(['enable', 'disable']).optional(),
  'remote-auth': z.enum(['enable', 'disable']).optional(),
  'remote-group': z.string().optional(),
  'password-expire': z.enum(['enable', 'disable']).optional(),
  'force-password-change': z.enum(['enable', 'disable']).optional(),
  'gui-dashboard': z.array(z.string()).optional(),
  'gui-global-menu-favorites': z.array(z.string()).optional(),
  'gui-vdom-menu-favorites': z.array(z.string()).optional(),
});

export const UpdateSystemAdminSchema = CreateSystemAdminSchema.partial().omit({ name: true });

// Esquemas para HA Config
export const UpdateHAConfigSchema = z.object({
  mode: z.enum(['standalone', 'a-p', 'a-a']).optional(),
  group_id: z.number().optional(),
  group_name: z.string().optional(),
  hbdev: z.string().optional(),
  priority: z.number().optional(),
  override: z.enum(['enable', 'disable']).optional(),
  'password': z.string().optional(),
  'monitor': z.array(z.string()).optional(),
  'pingserver-monitor-interface': z.array(z.string()).optional(),
  'pingserver-failover-threshold': z.number().optional(),
  'pingserver-slave-force-reset': z.enum(['enable', 'disable']).optional(),
  'ha-mgmt-status': z.enum(['enable', 'disable']).optional(),
  'ha-mgmt-interface': z.string().optional(),
  'ha-mgmt-interface-gateway': z.string().optional(),
  'session-pickup': z.enum(['enable', 'disable']).optional(),
  'session-pickup-connectionless': z.enum(['enable', 'disable']).optional(),
  'session-pickup-expectation': z.enum(['enable', 'disable']).optional(),
  'session-pickup-nat': z.enum(['enable', 'disable']).optional(),
  'session-pickup-delay': z.enum(['enable', 'disable']).optional(),
  'link-failed-signal': z.enum(['enable', 'disable']).optional(),
  'uninterruptible-upgrade': z.enum(['enable', 'disable']).optional(),
  'standalone-config-sync': z.enum(['enable', 'disable']).optional(),
  'ha-uptime-threshold': z.number().optional(),
});

// Esquemas para VDOM
export const CreateVDOMSchema = z.object({
  name: z.string().min(1, 'Nombre es requerido'),
  short_name: z.string().optional(),
  vcluster_id: z.number().optional(),
  temporary: z.number().optional(),
});

export const UpdateVDOMSchema = CreateVDOMSchema.partial().omit({ name: true });

// Esquemas para DHCP Server
export const CreateDHCPServerSchema = z.object({
  id: z.number().optional(),
  status: z.enum(['enable', 'disable']).optional(),
  'lease-time': z.number().optional(),
  'mac-acl-default-action': z.enum(['assign', 'block']).optional(),
  'forticlient-on-net-status': z.enum(['enable', 'disable']).optional(),
  'dns-server1': z.string().optional(),
  'dns-server2': z.string().optional(),
  'dns-server3': z.string().optional(),
  'dns-server4': z.string().optional(),
  'domain': z.string().optional(),
  'default-gateway': z.string().optional(),
  'netmask': z.string().optional(),
  interface: z.string(),
  'ip-range': z.array(z.object({
    id: z.number().optional(),
    'start-ip': z.string(),
    'end-ip': z.string(),
  })).optional(),
  'reserved-address': z.array(z.object({
    id: z.number().optional(),
    ip: z.string(),
    mac: z.string(),
    description: z.string().optional(),
    action: z.enum(['assign', 'block', 'reserved']).optional(),
    type: z.enum(['mac', 'option82']).optional(),
  })).optional(),
  'options': z.array(z.object({
    id: z.number().optional(),
    code: z.number(),
    type: z.enum(['hex', 'string', 'ip', 'fqdn']).optional(),
    value: z.string(),
  })).optional(),
});

export const UpdateDHCPServerSchema = CreateDHCPServerSchema.partial();

// Esquema de validación para parámetros de consulta
export const ListQuerySchema = z.object({
  vdom: z.string().optional(),
  filter: z.string().optional(),
  format: z.enum(['name_only', 'verbose']).optional(),
  scope: z.enum(['global', 'vdom']).optional(),
});

// Esquema para mover políticas
export const MovePolicySchema = z.object({
  policyid: z.number(),
  before: z.number().optional(),
  after: z.number().optional(),
  vdom: z.string().optional(),
});

// Exportar z para uso en otros módulos
export { z };

// Función helper para validar datos
export function validateData<T>(schema: z.ZodSchema<T>, data: unknown): T {
  return schema.parse(data);
}

// Función helper para validar datos de forma segura
export function safeValidateData<T>(schema: z.ZodSchema<T>, data: unknown): { success: true; data: T } | { success: false; error: z.ZodError } {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  } else {
    return { success: false, error: result.error };
  }
}

/**
 * Tipos esenciales para FortiGate API V7.6
 */

// Configuración de conexión
export interface FortiGateConfig {
  host: string;
  apiToken: string;
  port?: number;
  https?: boolean;
  verifySsl?: boolean;
  timeout?: number;
}

// Respuesta base de FortiGate API
export interface FortiGateResponse<T = unknown> {
  http_method: string;
  results: T;
  vdom: string;
  path: string;
  name: string;
  status: string;
  serial: string;
  version: string;
  build: number;
}

// Respuesta con error
export interface FortiGateErrorResponse {
  http_method?: string;
  status: string;
  http_status?: number;
  error?: string;
  message?: string;
  cli_error?: string;
}

// Firewall Policy
export interface FirewallPolicy {
  policyid?: number;
  name?: string;
  uuid?: string;
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  action: 'accept' | 'deny' | 'ipsec' | 'ssl-vpn';
  schedule?: string;
  service: string[] | string;
  logtraffic?: 'all' | 'utm' | 'disable';
  nat?: 'enable' | 'disable';
  status?: 'enable' | 'disable';
  comments?: string;
  groups?: string[];
  users?: string[];
  ips_sensor?: string;
  webfilter_profile?: string;
  dnsfilter_profile?: string;
  av_profile?: string;
  app_profile?: string;
  ssl_ssh_profile?: string;
  waf_profile?: string;
  profile_protocol_options?: string;
  profile_group?: string;
  poolname?: string[];
  capture_packet?: 'enable' | 'disable';
  ippool?: 'enable' | 'disable';
  fixedport?: 'enable' | 'disable';
  traffic_shaper?: string;
  traffic_shaper_reverse?: string;
  per_ip_shaper?: string;
  utm_status?: 'enable' | 'disable';
}

// Address Object
export interface AddressObject {
  name: string;
  uuid?: string;
  subnet?: string;
  type?: 'ipmask' | 'iprange' | 'fqdn' | 'geography' | 'wildcard' | 'wildcard-fqdn' | 'mac' | 'dynamic' | 'interface-subnet';
  start_ip?: string;
  end_ip?: string;
  fqdn?: string;
  country?: string;
  wildcard?: string;
  macaddr?: string[];
  interface?: string;
  comment?: string;
  associated_interface?: string;
  color?: number;
  allow_routing?: 'enable' | 'disable';
}

// Address Group
export interface AddressGroup {
  name: string;
  uuid?: string;
  member: string[] | string;
  comment?: string;
  color?: number;
  allow_routing?: 'enable' | 'disable';
}

// Service Object
export interface ServiceObject {
  name: string;
  category?: string;
  protocol?: 'TCP/UDP/SCTP' | 'ICMP' | 'ICMP6' | 'IP' | 'TCP' | 'UDP' | 'SCTP';
  tcp_portrange?: string[];
  udp_portrange?: string[];
  sctp_portrange?: string[];
  icmptype?: number;
  icmpcode?: number;
  comment?: string;
  color?: number;
}

// Service Group
export interface ServiceGroup {
  name: string;
  member: string[] | string;
  comment?: string;
  color?: number;
}

// VIP (Virtual IP)
export interface VIP {
  name: string;
  uuid?: string;
  extip: string;
  extintf: string[] | string;
  mappedip: string[] | string;
  type?: 'static-nat' | 'load-balance' | 'dnat' | 'server-load-balance';
  arp_reply?: 'enable' | 'disable';
  nat_source_vip?: 'enable' | 'disable';
  portforward?: 'enable' | 'disable';
  protocol?: 'tcp' | 'udp' | 'sctp';
  extport?: string;
  mappedport?: string;
  http_mapped_port?: number;
  ssl_certificate?: string;
  comment?: string;
  color?: number;
  src_filter?: string[];
  service?: string[];
  extaddr?: string[];
  mapped_addr?: string[];
  server_type?: 'http' | 'https' | 'imaps' | 'pop3s' | 'smtps' | 'ssl' | 'tcp' | 'udp' | 'ip';
  ldb_method?: 'static' | 'round-robin' | 'weighted' | 'least-session' | 'least-rtt' | 'first-alive' | 'http-host';
  realservers?: RealServer[];
  monitor?: string[];
  max_embryonic_connections?: number;
}

// Real Server
export interface RealServer {
  id: number;
  type?: 'ip' | 'address';
  ip?: string;
  address?: string;
  port?: number;
  status?: 'active' | 'standby' | 'disable';
  weight?: number;
  monitor?: string[];
}

// VIP Group
export interface VIPGroup {
  name: string;
  member: string[] | string;
  interface?: string;
  color?: number;
  comments?: string;
}

// Interface
export interface Interface {
  name: string;
  alias?: string;
  type?: 'physical' | 'vlan' | 'aggregate' | 'redundant' | 'tunnel' | 'vdom-link' | 'loopback' | 'wl-mesh' | 'switch' | 'hard-switch' | 'virtual-switch' | 'wl-ap' | 'fext-wan' | 'vxlan' | 'geneve' | 'ems' | 'ssl';
  vlanid?: number;
  interface?: string;
  ip?: string;
  allowaccess?: string;
  description?: string;
  status?: 'up' | 'down';
  mode?: 'static' | 'dhcp' | 'pppoe';
  macaddr?: string;
  speed?: 'auto' | '10full' | '10half' | '100full' | '100half' | '1000full' | '1000half' | '10000full';
  mtu?: number;
  role?: 'lan' | 'wan' | 'dmz' | 'undefined';
  vdom?: string;
}

// Static Route
export interface StaticRoute {
  seq_num: number;
  dst: string;
  gateway?: string;
  device?: string;
  distance?: number;
  weight?: number;
  priority?: number;
  comment?: string;
  blackhole?: 'enable' | 'disable';
  dynamic_gateway?: 'enable' | 'disable';
  sdwan?: 'enable' | 'disable';
  status?: 'enable' | 'disable';
}

// System Info
export interface SystemInfo {
  version: string;
  build: number;
  hostname: string;
  serial: string;
  model: string;
  model_name: string;
  model_number: string;
  model_short: string;
  firmware_version: string;
  firmware_build: string;
  current_minor: number;
  current_patch: number;
  system_uptime: string;
  log_disk_status: string;
  fortiguard_analytics: string;
  fortiguard_antispam: string;
  fortiguard_antivirus: string;
  fortiguard_webfilter: string;
  ha_mode: string;
  ha_group: number;
  ha_master_unit: boolean;
}

// VDOM
export interface VDOM {
  name: string;
  short_name?: string;
  vcluster_id?: number;
  ngfw_mode?: 'profile-based' | 'policy-based';
  opmode?: 'nat' | 'transparent';
  status?: 'active' | 'inactive';
  comments?: string;
}

// User Local
export interface UserLocal {
  name: string;
  status?: 'enable' | 'disable';
  type?: 'password' | 'radius' | 'tacacs-plus' | 'ldap' | 'fortitoken' | 'email' | 'sms' | 'external' | 'sso' | 'certificate' | 'two-factor';
  passwd?: string;
  ldap_server?: string;
  radius_server?: string;
  tacacs_plus_server?: string;
  two_factor?: 'disable' | 'fortitoken' | 'email' | 'sms';
  fortitoken?: string;
  email_to?: string;
  sms_server?: 'fortiguard' | 'custom';
  sms_custom_server?: string;
  authtimeout?: number;
}

// User Group
export interface UserGroup {
  name: string;
  member: Array<{ name: string }>;
  comment?: string;
  authtimeout?: number;
  group_type?: 'firewall' | 'directory-service' | 'fsso-service' | 'guest' | 'sso' | 'radius' | 'ldap';
}

// SSL VPN Settings
export interface SSLVPNSettings {
  status?: 'enable' | 'disable';
  reqclientcert?: 'enable' | 'disable';
  tlsv1_0?: 'enable' | 'disable';
  tlsv1_1?: 'enable' | 'disable';
  tlsv1_2?: 'enable' | 'disable';
  tlsv1_3?: 'enable' | 'disable';
  https_redirect?: 'enable' | 'disable';
  ssl_client_renegotiation?: 'allow' | 'deny' | 'secure';
  ssl_max_version?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_min_version?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  servercert?: string;
  port?: number;
  source_interface?: string[];
  source_address?: string[];
  default_portal?: string;
}

// VPN SSL Portal
export interface VPNSSLPortal {
  name: string;
  tunnel_mode?: 'enable' | 'disable';
  web_mode?: 'enable' | 'disable';
  ip_pools?: string[];
  ipv6_pools?: string[];
  split_tunneling?: 'enable' | 'disable';
  source_ip_pools?: string[];
  bookmark_group?: Array<{
    name: string;
    bookmarks?: Array<{
      name: string;
      apptype?: 'web' | 'telnet' | 'ssh' | 'ftp' | 'smb' | 'vnc' | 'rdp';
      url?: string;
      host?: string;
      port?: number;
    }>;
  }>;
  theme?: 'blue' | 'green' | 'melongene' | 'red' | 'maroon' | 'gray';
  forticlient_download?: 'enable' | 'disable';
  display_connection_tools?: 'enable' | 'disable';
  display_history?: 'enable' | 'disable';
  display_status?: 'enable' | 'disable';
}

// VPN IPsec Phase1
export interface VPNIPsecPhase1 {
  name: string;
  type?: 'static' | 'dynamic';
  interface?: string;
  ike_version?: '1' | '2';
  peertype?: 'any' | 'one' | 'dialup' | 'peer' | 'peergrp';
  proposal?: string[];
  local_gw?: string;
  remote_gw?: string;
  psksecret?: string;
  certificate?: string[];
  peerid?: string;
  peer?: string[];
  peergrp?: string;
  mode?: 'aggressive' | 'main';
  mode_cfg?: 'enable' | 'disable';
  ipv4_start_ip?: string;
  ipv4_end_ip?: string;
  ipv4_netmask?: number;
  xauthtype?: 'disable' | 'client' | 'pap' | 'chap' | 'auto';
  authusr?: string;
  authpasswd?: string;
  dhgrp?: string[];
  keylifeseconds?: number;
  rekey?: 'enable' | 'disable';
  dpd?: 'disable' | 'on-idle' | 'on-demand';
  comments?: string;
}

// VPN IPsec Phase2
export interface VPNIPsecPhase2 {
  name: string;
  phase1name: string;
  proposal?: string[];
  dhgrp?: string[];
  keylifeseconds?: number;
  src_subnet?: string;
  src_start_ip?: string;
  src_end_ip?: string;
  dst_subnet?: string;
  dst_start_ip?: string;
  dst_end_ip?: string;
  encapsulation?: 'tunnel-mode' | 'transport-mode';
  pfs?: 'enable' | 'disable';
  comments?: string;
}

// Log Settings
export interface LogSettings {
  status?: 'enable' | 'disable';
  ips_archive?: 'enable' | 'disable';
  fwpolicy_implicit_log?: 'enable' | 'disable';
  log_invalid_packet?: 'enable' | 'disable';
  local_in_policy_log?: 'enable' | 'disable';
  nat_policy_log?: 'enable' | 'disable';
  utm_log?: 'enable' | 'disable';
  web_proxy_log?: 'enable' | 'disable';
}

// Log FortiAnalyzer Settings
export interface LogFortiAnalyzerSettings {
  status?: 'enable' | 'disable';
  server?: string;
  reliable?: 'enable' | 'disable';
  upload_time?: 'daily' | 'weekly' | 'hourly';
  upload_day?: 'sunday' | 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday';
}

// Log Syslog Settings
export interface LogSyslogSettings {
  status?: 'enable' | 'disable';
  server?: string;
  mode?: 'udp' | 'legacy-reliable' | 'reliable';
  port?: number;
  facility?: 'kernel' | 'user' | 'mail' | 'daemon' | 'auth' | 'syslog' | 'lpr' | 'news' | 'uucp' | 'cron' | 'authpriv' | 'ftp' | 'ntp' | 'audit' | 'alert' | 'clock' | 'local0' | 'local1' | 'local2' | 'local3' | 'local4' | 'local5' | 'local6' | 'local7';
  format?: 'default' | 'csv' | 'cef';
}

// Log Disk Settings
export interface LogDiskSettings {
  status?: 'enable' | 'disable';
  severity?: 'emergency' | 'alert' | 'critical' | 'error' | 'warning' | 'notification' | 'information' | 'debug';
  ips_archive?: 'enable' | 'disable';
  roll_schedule?: 'daily' | 'weekly';
  roll_day?: 'sunday' | 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday';
}

// Log Event Filter
export interface LogEventFilter {
  severity?: 'emergency' | 'alert' | 'critical' | 'error' | 'warning' | 'notification' | 'information' | 'debug';
  system?: 'enable' | 'disable';
  vpn?: 'enable' | 'disable';
  user?: 'enable' | 'disable';
  security?: 'enable' | 'disable';
  ha?: 'enable' | 'disable';
}

// Log Traffic Filter
export interface LogTrafficFilter {
  severity?: 'emergency' | 'alert' | 'critical' | 'error' | 'warning' | 'notification' | 'information' | 'debug';
  local_traffic?: 'enable' | 'disable';
  multicast_traffic?: 'enable' | 'disable';
  forwarded_traffic?: 'enable' | 'disable';
}

// Antivirus Profile
export interface AntivirusProfile {
  name: string;
  comment?: string;
  inspection_mode?: 'proxy' | 'flow';
  ftgd_analytics?: 'disable' | 'suspicious' | 'everything';
}

// Web Filter Profile
export interface WebFilterProfile {
  name: string;
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  https_replacemsg?: 'enable' | 'disable';
  inspection_mode?: 'proxy' | 'flow';
}

// DNS Filter Profile
export interface DNSFilterProfile {
  name: string;
  comment?: string;
  block_action?: 'block' | 'redirect';
  redirect_portal?: string;
  safe_search?: 'disable' | 'enforce';
  log_all_domain?: 'enable' | 'disable';
}

// Application Control Profile
export interface ApplicationControlProfile {
  name: string;
  comment?: string;
  other_application_log?: 'enable' | 'disable';
  other_application_action?: 'pass' | 'block';
  unknown_application_log?: 'enable' | 'disable';
  unknown_application_action?: 'pass' | 'block';
}

// IPS Sensor
export interface IPSSensor {
  name: string;
  comment?: string;
  block_malicious_url?: 'enable' | 'disable';
  scan_botnet_connections?: 'disable' | 'block' | 'monitor';
}

// SSL/SSH Profile
export interface SSLSSHProfile {
  name: string;
  comment?: string;
  ssl?: SSLProtocolOptions;
  https?: HTTPSOptions;
  ftps?: FTPSOptions;
  imaps?: IMAPSOptions;
  pop3s?: POP3SOptions;
  smtps?: SMTPOptions;
  ssh?: SSHOptions;
}

interface SSLProtocolOptions {
  inspect_all?: 'disable' | 'certificate-inspection' | 'deep-inspection';
  unsupported_ssl_cipher?: 'allow' | 'block';
  invalid_server_cert?: 'allow' | 'block';
}

interface HTTPSOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection' | 'certificate-inspection';
  client_cert_request?: 'bypass' | 'inspect' | 'block';
}

interface FTPSOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection' | 'certificate-inspection';
}

interface IMAPSOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection' | 'certificate-inspection';
}

interface POP3SOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection' | 'certificate-inspection';
}

interface SMTPOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection' | 'certificate-inspection';
}

interface SSHOptions {
  ports?: number;
  status?: 'disable' | 'deep-inspection';
}

// HA Configuration
export interface HAConfig {
  mode?: 'standalone' | 'a-p' | 'a-a';
  group_id?: number;
  group_name?: string;
  hb_dev?: string[];
  hb_interval?: number;
  hb_lost_threshold?: number;
  priority?: number;
  override?: 'enable' | 'disable';
  session_pickup?: 'enable' | 'disable';
  ha_mgmt_status?: 'enable' | 'disable';
  monitor?: string[];
}

// System Admin
export interface SystemAdmin {
  name: string;
  wildcard?: 'enable' | 'disable';
  remote_auth?: 'enable' | 'disable';
  remote_group?: string;
  password?: string;
  trusthost1?: string;
  trusthost2?: string;
  trusthost3?: string;
  accprofile?: string;
  comments?: string;
  vdom?: string[];
}

// System Global
export interface SystemGlobal {
  language?: 'english' | 'simch' | 'japanese' | 'korean' | 'spanish' | 'trach';
  gui_ipv6?: 'enable' | 'disable';
  gui_certificates?: 'enable' | 'disable';
  gui_device_latitude?: string;
  gui_device_longitude?: string;
  timezone?: string;
}

// FortiGuard Configuration
export interface FortiGuardConfig {
  port?: '53' | '8888' | '80' | '443';
  protocol?: 'udp' | 'http' | 'https';
  antivirus_cache?: 'enable' | 'disable';
  web_filter_cache?: 'enable' | 'disable';
}

// SD-WAN Configuration
export interface SDWANConfig {
  status?: 'enable' | 'disable';
  load_balance_mode?: 'source-ip' | 'weight' | 'usage' | 'source-dest-ip' | 'measured-volume-based';
}

// Zone
export interface Zone {
  name: string;
  description?: string;
  interface?: string[];
  intrazone?: 'allow' | 'deny';
}

// Firewall Schedule Recurring
export interface FirewallScheduleRecurring {
  name: string;
  day?: string;
  start?: string;
  end?: string;
  color?: number;
}

// Firewall Schedule Onetime
export interface FirewallScheduleOnetime {
  name: string;
  start?: string;
  end?: string;
  color?: number;
}

// Firewall Schedule Group
export interface FirewallScheduleGroup {
  name: string;
  member?: string[];
  color?: number;
}

// Firewall Local-in Policy
export interface FirewallLocalInPolicy {
  policyid?: number;
  uuid?: string;
  intf: string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  action: 'accept' | 'deny';
  service: string[] | string;
  schedule?: string;
  status?: 'enable' | 'disable';
  comments?: string;
}

// Firewall Multicast Policy
export interface FirewallMulticastPolicy {
  policyid?: number;
  name?: string;
  uuid?: string;
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  action: 'accept' | 'deny';
  protocol?: number;
  schedule?: string;
  status?: 'enable' | 'disable';
  comments?: string;
}

// Firewall DNAT
export interface FirewallDNAT {
  policyid?: number;
  name?: string;
  uuid?: string;
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  service: string[] | string;
  nat: 'enable' | 'disable';
  protocol?: 'tcp' | 'udp' | 'sctp';
  extport?: string;
  mappedport?: string;
  comments?: string;
  status?: 'enable' | 'disable';
}

// Central NAT
export interface CentralNAT {
  policyid?: number;
  uuid?: string;
  status?: 'enable' | 'disable';
}

// System API User
export interface SystemAPIUser {
  name: string;
  api_key?: string[];
  accprofile?: string;
  vdom?: string[];
  schedule?: string;
  trusthost?: string[];
}

// System SNMP User
export interface SystemSNMPUser {
  name: string;
  notify_hosts?: string;
  trap_status?: 'enable' | 'disable';
  priv_proto?: 'aes' | 'des' | 'aes256' | 'aes256cisco';
  priv_pwd?: string;
  auth_proto?: 'md5' | 'sha' | 'sha224' | 'sha256' | 'sha384' | 'sha512';
  auth_pwd?: string;
  security_level?: 'no-auth-no-priv' | 'auth-no-priv' | 'auth-priv';
  queries?: 'enable' | 'disable';
}

// System SNMP Community
export interface SystemSNMPCommunity {
  id: number;
  name?: string;
  status?: 'enable' | 'disable';
  trap_v1_status?: 'enable' | 'disable';
  trap_v2c_status?: 'enable' | 'disable';
}

// System Automation Stitch
export interface SystemAutomationStitch {
  name: string;
  status?: 'enable' | 'disable';
  trigger?: string[];
}

// System Automation Trigger
export interface SystemAutomationTrigger {
  name: string;
  trigger_type?: 'event-based' | 'scheduled';
  event_type?: string;
  logid?: number[];
}

// System Replacemsg Group
export interface SystemReplacemsgGroup {
  name: string;
  comment?: string;
}

// System Session Helper
export interface SystemSessionHelper {
  name: string;
  protocol?: number;
  port?: number;
  id?: number;
}

// System DHCP Server
export interface SystemDHCPServer {
  id: number;
  status?: 'enable' | 'disable';
  lease_time?: number;
  interface?: string;
  ip_range?: Array<{
    id: number;
    start_ip?: string;
    end_ip?: string;
  }>;
  dns_server1?: string;
  dns_server2?: string;
  default_gateway?: string;
}

// System Settings
export interface SystemSettings {
  comments?: string;
  opmode?: 'nat' | 'transparent';
  ngfw_mode?: 'profile-based' | 'policy-based';
  inspection_mode?: 'proxy' | 'flow';
  ssl_ssh_profile?: string;
}

// System Link Monitor
export interface SystemLinkMonitor {
  name: string;
  addr_mode?: 'ipv4' | 'ipv6';
  srcintf?: string;
  server?: string[];
  protocol?: 'ping' | 'tcp-echo' | 'udp-echo' | 'http' | 'twamp' | 'dns' | 'tcp-connect' | 'ftp' | 'https';
  port?: number;
  gateway_ip?: '0.0.0.0' | 'primary' | 'secondary';
  interval?: number;
  failtime?: number;
  recoverytime?: number;
}

// System Virtual Switch
export interface SystemVirtualSwitch {
  name: string;
  physical_switch?: string;
  vlan?: number;
}

// System Virtual Wire Pair
export interface SystemVirtualWirePair {
  name: string;
  member?: string[];
  wildcard_vlan?: 'enable' | 'disable';
}

// System Vxlan
export interface SystemVxlan {
  name: string;
  interface?: string;
  vni?: number;
  ip_version?: 'ipv4' | 'ipv6';
  remote_ip?: string[];
  dstport?: number;
}

// System GRE Tunnel
export interface SystemGRETunnel {
  name: string;
  interface?: string;
  ip_version?: 'ipv4' | 'ipv6';
  remote_gw?: string;
  local_gw?: string;
  keepalive_interval?: number;
  keepalive_failtimes?: number;
}

// System PPPoE Interface
export interface SystemPPPoEInterface {
  name: string;
  dial_on_demand?: 'enable' | 'disable';
  mtu?: number;
  username?: string;
  password?: string;
}

// System Geoip Override
export interface SystemGeoipOverride {
  name: string;
  description?: string;
  country_id?: number;
}

// System FIPS-CC
export interface SystemFIPSCC {
  status?: 'enable' | 'disable';
  entropy_token?: 'enable' | 'disable';
}

// WAF Profile
export interface WAFProfile {
  name: string;
  comment?: string;
  extended_log?: 'enable' | 'disable';
}

// Proxy Policy
export interface ProxyPolicy {
  policyid?: number;
  name?: string;
  uuid?: string;
  proxy?: 'explicit-web' | 'transparent-web' | 'ftp' | 'ssh' | 'ssh-host-key' | 'wanopt' | 'ztna';
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  service: string[] | string;
  action: 'accept' | 'deny' | 'redirect';
  status?: 'enable' | 'disable';
  schedule?: string;
  comments?: string;
}

// Traffic Shaper
export interface TrafficShaper {
  name: string;
  guarantee?: number;
  maximum?: number;
  bandwidth_unit?: 'kbps' | 'mbps' | 'gbps';
  priority?: 'high' | 'medium-high' | 'medium' | 'medium-low' | 'low';
}

// Traffic Shaper Per-IP
export interface TrafficShaperPerIP {
  name: string;
  maximum_bandwidth?: number;
  bandwidth_unit?: 'kbps' | 'mbps' | 'gbps';
  max_concurrent_session?: number;
}

// Certificate
export interface Certificate {
  name: string;
  type?: 'local' | 'ca' | 'remote' | 'crl' | 'pkcs12';
  password?: string;
  comments?: string;
}

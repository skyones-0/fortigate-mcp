/**
 * Tipos extendidos para FortiGate API V7.6
 * Funcionalidades adicionales no cubiertas en fortigate.ts
 */

// ============================================
// NAT Avanzado
// ============================================

export interface NAT46Policy {
  policyid?: number;
  name?: string;
  status?: 'enable' | 'disable';
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr: string[] | string;
  dstaddr: string[] | string;
  action: 'accept' | 'deny';
  schedule?: string;
  service: string[] | string;
  comments?: string;
}

export interface CentralNATEntry {
  policyid?: number;
  uuid?: string;
  status?: 'enable' | 'disable';
  orig_addr: string[] | string;
  orig_port?: string;
  nat_ippool?: string[];
  nat_port?: string;
  protocol?: 'tcp' | 'udp' | 'sctp' | 'icmp' | 'http' | 'https';
  comments?: string;
}

// ============================================
// Security Profiles Extendidos
// ============================================

export interface WAFProfileExtended {
  name: string;
  comment?: string;
  extended_log?: 'enable' | 'disable';
  signature?: WAFSignatureSettings;
  constraint?: WAFConstraintSettings;
  method?: WAFMethodSettings;
  url_access?: WAFURLAccessSettings;
}

export interface WAFSignatureSettings {
  main_class?: WAFMainClassSignature[];
}

export interface WAFMainClassSignature {
  id?: number;
  status?: 'enable' | 'disable';
  action?: 'allow' | 'block' | 'monitor';
  log?: 'enable' | 'disable';
}

export interface WAFConstraintSettings {
  status?: 'enable' | 'disable';
  max_cookie_len?: number;
  max_header_line_request?: number;
  max_range_segment?: number;
  max_url_param?: number;
}

export interface WAFMethodSettings {
  status?: 'enable' | 'disable';
  allowed_methods?: string;
}

export interface WAFURLAccessSettings {
  status?: 'enable' | 'disable';
  access_pattern?: WAFAccessPattern[];
}

export interface WAFAccessPattern {
  id?: number;
  pattern?: string;
  regex?: 'enable' | 'disable';
  negation?: 'enable' | 'disable';
  action?: 'allow' | 'block' | 'monitor';
}

export interface EmailFilterProfile {
  name: string;
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  inspection_mode?: 'proxy' | 'flow';
  pop3?: EmailFilterProtocol;
  imap?: EmailFilterProtocol;
  smtp?: EmailFilterProtocol;
  mapi?: EmailFilterProtocol;
  msn_hotmail?: EmailFilterProtocol;
  yahoo_mail?: EmailFilterProtocol;
  gmail?: EmailFilterProtocol;
  other_webmails?: EmailFilterProtocol;
}

export interface EmailFilterProtocol {
  log?: 'enable' | 'disable';
  action?: 'pass' | 'tag' | 'discard';
}

export interface DLPProfile {
  name: string;
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  inspection_mode?: 'proxy' | 'flow';
  rule?: DLPProfileRule[];
}

export interface DLPProfileRule {
  id?: number;
  name?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  protocol?: string;
  filter_by?: 'sensor' | 'mip' | 'fingerprint';
  sensor?: string;
  action?: 'log-only' | 'block' | 'quarantine-ip' | 'ban' | 'ban-sender';
  status?: 'enable' | 'disable';
}

export interface FileFilterProfile {
  name: string;
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  inspection_mode?: 'proxy' | 'flow';
  log?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  rules?: FileFilterRule[];
}

export interface FileFilterRule {
  id?: number;
  name?: string;
  comment?: string;
  action?: 'log' | 'block';
  log?: 'enable' | 'disable';
  filter?: FileFilterCriteria[];
}

export interface FileFilterCriteria {
  type?: 'file-type' | 'file-name' | 'file-size';
  file_type?: string[];
  file_name?: string;
  file_size?: number;
}

export interface VoIPProfile {
  name: string;
  comment?: string;
  sccp?: VoIPProtocol;
  sip?: VoIPProtocol;
  feature_set?: 'proxy' | 'flow';
}

export interface VoIPProtocol {
  status?: 'enable' | 'disable';
  log_call_summary?: 'enable' | 'disable';
  log_violations?: 'enable' | 'disable';
  action?: 'pass' | 'block';
}

export interface SCTPFilterProfile {
  name: string;
  comment?: string;
  sctp_filtering?: 'enable' | 'disable';
  sctp_data_csum?: 'validate' | 'ignore';
}

export interface VirtualPatchProfile {
  name: string;
  comment?: string;
  nac_report?: 'enable' | 'disable';
  nac_policy?: string[];
}

// ============================================
// VPN Extendido
// ============================================

export interface SSLVPNRealm {
  url_path?: string;
  virtual_host?: string;
  login_page?: string;
  limit_user_logins?: 'enable' | 'disable';
}

export interface SSLVPNBookmark {
  name: string;
  apptype?: 'web' | 'telnet' | 'ssh' | 'ftp' | 'smb' | 'vnc' | 'rdp' | 'citrix' | 'rdp-native' | 'portforward';
  url?: string;
  host?: string;
  port?: number;
  preconnection_id?: number;
  preconnection_blob?: string;
  security?: 'rdp' | 'nla' | 'tls' | 'any';
  server_layout?: 'en-us-qwerty' | 'en-gb-qwerty' | 'es-es-qwerty' | 'fr-fr-azerty' | 'fr-ch-qwerty' | 'de-de-qwerty' | 'de-ch-qwerty';
  description?: string;
}

export interface IPsecPhase1Proposal {
  name: string;
  encryption?: string[];
  authentication?: string[];
  dhgrp?: string[];
}

export interface IPsecPhase2Proposal {
  name: string;
  encryption?: string[];
  authentication?: string[];
  dhgrp?: string[];
}

export interface GRETunnel {
  name: string;
  interface?: string;
  ip_version?: 'ipv4' | 'ipv6';
  remote_gw?: string;
  local_gw?: string;
  mode?: 'IPv4' | 'IPv6';
  keepalive_interval?: number;
  keepalive_failtimes?: number;
}

export interface L2TPSettings {
  status?: 'enable' | 'disable';
  eip?: string;
  sip?: string;
  usrgrp?: string;
  auth_type?: 'auto' | 'mschapv2' | 'mschap' | 'chap' | 'pap';
}

// ============================================
// Routing Extendido
// ============================================

export interface BGPNeighbor {
  ip: string;
  remote_as?: number;
  activate?: 'enable' | 'disable';
  attribute_unchanged?: string;
  ebgp_multihop_ttl?: number;
  weight?: number;
  route_map_in?: string;
  route_map_out?: string;
  prefix_list_in?: string;
  prefix_list_out?: string;
}

export interface BGPNeighborGroup {
  name: string;
  remote_as?: number;
  route_map_in?: string;
  route_map_out?: string;
}

export interface OSPFArea {
  id: string;
  type?: 'regular' | 'nssa' | 'stub';
  nssa_default_information_originate?: 'enable' | 'disable';
  nssa_default_information_metric?: number;
  nssa_default_information_metric_type?: 1 | 2;
  range?: OSPFRange[];
}

export interface OSPFRange {
  id?: number;
  prefix?: string;
  advertise?: 'enable' | 'disable';
}

export interface OSPFInterface {
  name: string;
  interface?: string;
  area?: string;
  network_type?: 'broadcast' | 'non-broadcast' | 'point-to-point' | 'point-to-multipoint';
  cost?: number;
  priority?: number;
  bfd?: 'enable' | 'disable';
  mtu_ignore?: 'enable' | 'disable';
  dead_interval?: number;
  hello_interval?: number;
}

export interface PolicyRoute {
  policyid?: number;
  name?: string;
  status?: 'enable' | 'disable';
  input_device?: string[];
  srcaddr?: string[];
  dstaddr?: string[];
  internet_service?: string[];
  action?: 'forward' | 'next';
  output_device?: string;
  gateway?: string;
  tos?: string;
  tos_mask?: string;
}

// ============================================
// SD-WAN Extendido
// ============================================

export interface SDWANRule {
  id?: number;
  name?: string;
  status?: 'enable' | 'disable';
  'srcintf'?: string[];
  'dstintf'?: string[];
  srcaddr?: string[];
  dstaddr?: string[];
  internet_service?: string[];
  mode?: 'auto' | 'manual' | 'priority' | 'sla' | 'load-balance';
  priority_members?: string[];
  required_bandwidth?: number;
  quality_link?: number;
}

export interface SDWANHealthCheck {
  name: string;
  server?: string[];
  protocol?: 'ping' | 'tcp-echo' | 'udp-echo' | 'http' | 'twamp' | 'dns' | 'tcp-connect' | 'ftp' | 'https';
  port?: number;
  detect_mode?: 'active' | 'passive' | 'prefer-passive' | 'remote';
  interval?: number;
  failure_before_inactive?: number;
  sla?: SDWANSLA[];
}

export interface SDWANSLA {
  id?: number;
  link_cost_factor?: string;
  latency_threshold?: number;
  jitter_threshold?: number;
  packetloss_threshold?: number;
}

export interface SDWANZone {
  name: string;
  interface?: string[];
  service_sla_tie_break?: 'cfg-order' | 'fib-best-match' | 'input-device';
}

// ============================================
// System & Management
// ============================================

export interface AccessProfile {
  name: string;
  permission?: {
    sys_admin?: AccessProfilePermission;
    sys_cfg?: AccessProfilePermission;
    netcfg?: AccessProfilePermission;
    log_and_report?: AccessProfilePermission;
    vpnmgr?: AccessProfilePermission;
    utmgrp?: AccessProfilePermission;
    wifi?: AccessProfilePermission;
  };
}

export interface AccessProfilePermission {
  read?: 'enable' | 'disable';
  write?: 'enable' | 'disable';
}

export interface APIUser {
  name: string;
  api_key?: string[];
  accprofile?: string;
  vdom?: string[];
  schedule?: string;
  cors_allow_origin?: string;
  peer_auth?: 'enable' | 'disable';
  peer_group?: string;
  trusthost?: string[];
}

export interface AutomationScript {
  name: string;
  type?: 'cli' | 'python';
  target?: 'device' | 'remote';
  description?: string;
  content?: string;
}

export interface AutomationAction {
  name: string;
  action_type?: 'email' | 'fortiguard-ioc-query' | 'disable-ssid' | 'quarantine' | 'quarantine-forticlient' | 'aws-lambda' | 'azure-function' | 'google-cloud-function' | 'alicloud-function' | 'cli-script' | 'notification';
  email?: AutomationActionEmail;
  'aws_lambda'?: AutomationActionAWSLambda;
  'azure_function'?: AutomationActionAzureFunction;
  'cli_script'?: string;
}

export interface AutomationActionEmail {
  from?: string;
  to?: string[];
  subject?: string;
  body?: string;
}

export interface AutomationActionAWSLambda {
  region?: string;
  function_name?: string;
  access_key_id?: string;
  secret_access_key?: string;
}

export interface AutomationActionAzureFunction {
  domain?: string;
  function_name?: string;
  key?: string;
}

export interface CertificateCA {
  name: string;
  ca?: string;
  range?: string;
  source?: 'factory' | 'user' | 'bundle';
  comments?: string;
}

export interface CertificateCSR {
  name: string;
  id_type?: 'host-ip' | 'domain-name' | 'email';
  id_value?: string;
  organization?: string;
  unit?: string;
  country?: string;
  state?: string;
  city?: string;
  email?: string;
  key_type?: 'RSA' | 'EC';
  key_size?: 512 | 1024 | 1536 | 2048 | 4096;
}

export interface FirmwareVersion {
  version?: string;
  build?: number;
  release_date?: string;
  release_notes?: string;
  filename?: string;
  size?: number;
  checksum?: string;
}

export interface FirmwareStatus {
  current_version?: string;
  current_build?: number;
  available_versions?: FirmwareVersion[];
  upgrade_available?: boolean;
}

export interface FortiManager {
  fmg_ip?: string;
  fmg_secondary_ip?: string;
  fmg_serial?: string;
  fmg_status?: 'connected' | 'disconnected';
  fmg_reg_status?: 'registered' | 'unregistered';
}

export interface FortiCloud {
  status?: 'not_registered' | 'registered';
  email?: string;
}

export interface VDOMLink {
  name: string;
  vcluster?: string;
  peer?: string;
}

export interface VDOMProperty {
  vdom: string;
  name?: string;
  description?: string;
  ngfw_mode?: 'profile-based' | 'policy-based';
  opmode?: 'nat' | 'transparent';
  status?: 'active' | 'inactive';
  settings?: Record<string, unknown>;
}

// ============================================
// Switch & Wireless
// ============================================

export interface SwitchInterface {
  name: string;
  type?: 'physical' | 'trunk';
  allowed_vlans?: string[];
  untagged_vlans?: string[];
  vlan?: number;
  stp?: 'enable' | 'disable';
  stp_edged_port?: 'enable' | 'disable';
}

export interface SwitchVLAN {
  id: number;
  name?: string;
  description?: string;
  member?: string[];
  color?: number;
}

export interface MCLAG {
  domain?: number;
  peer_ip?: string;
  peer_ip6?: string;
  src_intf?: string;
  trunk_members?: string[];
}

export interface WirelessAPProfile {
  name: string;
  comment?: string;
  acs?: APProfileACS;
  handoff?: APProfileHandoff;
  performance?: APProfilePerformance;
}

export interface APProfileACS {
  fragment_threshold?: number;
  rts_threshold?: number;
  channel?: string;
  tx_power?: number;
}

export interface APProfileHandoff {
  roam_signal?: number;
  handoff_signal?: number;
}

export interface APProfilePerformance {
  max_clients?: number;
  max_wids?: number;
  frequency?: '2.4GHz' | '5GHz' | '6GHz';
}

export interface WirelessAP {
  name: string;
  wtp_id?: string;
  wtp_mode?: 'normal' | 'remote' | 'client';
  ap_profile?: string;
  region_code?: string;
  admin?: 'discovered' | 'disable' | 'enable';
  ip_addr?: string;
  conn_status?: 'connected' | 'disconnected' | 'offline';
}

export interface WirelessSSID {
  name: string;
  traffic_mode?: 'tunnel' | 'local-bridge' | 'bridge';
  security?: SSIDSecurity;
  pmf?: SSIDPMF;
  mac_filter?: string;
  vlan_id?: number;
}

export interface SSIDSecurity {
  mode?: 'open' | 'captive-portal' | 'wpa2-only-personal' | 'wpa2-personal' | 'wpa2-only-enterprise' | 'wpa2-enterprise' | 'wpa3-enterprise' | 'wpa3-only-enterprise' | 'wpa3-personal' | 'wpa3-only-personal';
  encryption?: 'tkip' | 'aes' | 'tkip-aes';
  passphrase?: string;
  pmf?: 'disable' | 'enable' | 'optional';
}

export interface SSIDPMF {
  status?: 'disable' | 'enable' | 'optional';
}

// ============================================
// Network Features
// ============================================

export interface VirtualSwitch {
  name: string;
  physical_switch?: string;
  vlan?: number;
  port?: VirtualSwitchPort[];
}

export interface VirtualSwitchPort {
  name?: string;
  vlan?: number;
  type?: 'access' | 'trunk';
}

export interface IPv6Policy {
  policyid?: number;
  name?: string;
  uuid?: string;
  srcintf: string[] | string;
  dstintf: string[] | string;
  srcaddr6: string[] | string;
  dstaddr6: string[] | string;
  action: 'accept' | 'deny' | 'ipsec' | 'ssl-vpn';
  schedule?: string;
  service: string[] | string;
  logtraffic?: 'all' | 'utm' | 'disable';
  status?: 'enable' | 'disable';
  comments?: string;
}

// ============================================
// ZTNA (Zero Trust Network Access)
// ============================================

export interface ZTNAGateway {
  name: string;
  service?: 'ztna';
  ztna_device_ownership?: 'enable' | 'disable';
  ztna_ems_tag_check?: 'enable' | 'disable';
  ztna_policy_redirect?: 'enable' | 'disable';
  auth_virtual_host?: string;
}

export interface ZTNAProxy {
  name: string;
  ztna_gateway?: string;
  ztna_service?: string;
  server?: string[];
  port?: number;
  protocol?: 'tcp' | 'udp';
}

export interface ZTNATag {
  name: string;
  type?: 'ems_tag';
  ems_tag?: string;
}

// ============================================
// SAML & Authentication
// ============================================

export interface SAMLServer {
  name: string;
  entity_id?: string;
  idp_entity_id?: string;
  idp_single_sign_on_url?: string;
  idp_single_logout_url?: string;
  idp_cert?: string;
  sp_cert?: string;
  digest_method?: 'sha1' | 'sha256' | 'sha384' | 'sha512';
}

export interface FortiToken {
  serial_number: string;
  status?: 'active' | 'pending' | 'disabled';
  license?: string;
  activation_code?: string;
}

export interface FSSOAgent {
  name: string;
  status?: 'enable' | 'disable';
  type?: 'default' | 'exchange' | 'lync' | 'oracle' | 'sct';
  ldap_server?: string;
  listen_port?: number;
}

// ============================================
// Logging & Reporting
// ============================================

export interface LogFilter {
  id?: number;
  severity?: string;
  module?: string;
  action?: string;
}

export interface FortiAnalyzerSettings {
  status?: 'enable' | 'disable';
  server?: string;
  source_ip?: string;
  upload_option?: 'store-and-upload' | 'realtime' | '1-minute' | '5-minute';
  reliable?: 'enable' | 'disable';
  certificate_verification?: 'enable' | 'disable';
}

export interface SyslogServer {
  name: string;
  server?: string;
  port?: number;
  mode?: 'udp' | 'legacy-reliable' | 'reliable';
  facility?: 'kernel' | 'user' | 'mail' | 'daemon' | 'auth' | 'syslog' | 'lpr' | 'news' | 'uucp' | 'cron' | 'authpriv' | 'ftp' | 'ntp' | 'audit' | 'alert' | 'clock' | 'local0' | 'local1' | 'local2' | 'local3' | 'local4' | 'local5' | 'local6' | 'local7';
  format?: 'default' | 'csv' | 'cef';
  filter?: string;
}

export interface ReportConfig {
  name: string;
  title?: string;
  subtitle?: string;
  description?: string;
  style_theme?: 'green' | 'red' | 'blue' | 'brown';
  settings?: ReportSettings;
  layout?: ReportLayout;
}

export interface ReportSettings {
  pdf_report?: 'enable' | 'disable';
  fortiview?: 'enable' | 'disable';
  web_browsing?: 'enable' | 'disable';
  application_usage?: 'enable' | 'disable';
}

export interface ReportLayout {
  paper?: 'a4' | 'letter';
  column_break_before?: string[];
  page_break_before?: string[];
}

// ============================================
// Monitoring & Diagnostics
// ============================================

export interface SystemHealth {
  cpu?: HealthMetric[];
  memory?: HealthMetric[];
  disk?: HealthMetric[];
  session?: HealthMetric[];
}

export interface HealthMetric {
  current?: number;
  average?: number;
  maximum?: number;
  minimum?: number;
}

export interface InterfaceStats {
  name: string;
  rx_packets?: number;
  tx_packets?: number;
  rx_bytes?: number;
  tx_bytes?: number;
  rx_errors?: number;
  tx_errors?: number;
  rx_dropped?: number;
  tx_dropped?: number;
  collisions?: number;
}

export interface PacketCapture {
  interface: string;
  max_packet_count?: number;
  filters?: CaptureFilter;
  status?: 'running' | 'stopped';
  filename?: string;
}

export interface CaptureFilter {
  host?: string;
  port?: number;
  protocol?: 'icmp' | 'tcp' | 'udp';
  src_host?: string;
  dst_host?: string;
}

export interface PingResult {
  target_ip?: string;
  packet_loss?: number;
  min_rtt?: number;
  max_rtt?: number;
  avg_rtt?: number;
  results?: string[];
}

export interface TracerouteResult {
  target_ip?: string;
  hops?: TracerouteHop[];
}

export interface TracerouteHop {
  hop?: number;
  ip?: string;
  hostname?: string;
  rtt?: number;
}

/**
 * Tipos principales para FortiGate MCP V7.6
 */

// Configuración de conexión a FortiGate
export interface FortiGateConfig {
  host: string;
  port?: number;
  token: string;
  https?: boolean;
  verifySsl?: boolean;
  timeout?: number;
  vdom?: string;
}

// Respuesta genérica de la API de FortiGate
export interface FortiGateApiResponse<T = any> {
  http_method: string;
  size: number;
  limit_reached: boolean;
  matched_count: number;
  next_idx?: number;
  revision: string;
  results: T[];
  vdom: string;
  path: string;
  name: string;
  status: string;
  http_status: number;
  serial: string;
  version: string;
  build: number;
}

// Error de la API de FortiGate
export interface FortiGateApiError {
  status: string;
  http_status: number;
  error_code?: number;
  error_message?: string;
  details?: string;
}

// Información del sistema
export interface SystemInfo {
  hostname: string;
  serial: string;
  version: string;
  build: number;
  model: string;
  model_name: string;
  model_number: string;
  model_serial: string;
  uptime: string;
  current_time: string;
  last_reboot_reason: string;
  fortiguard_version: string;
}

// Estado de cambio
export interface ChangeState {
  id: string;
  timestamp: Date;
  operation: 'create' | 'update' | 'delete';
  module: string;
  resource: string;
  previousState?: any;
  newState?: any;
  vdom: string;
  user?: string;
  description?: string;
  rollbackAvailable: boolean;
}

// Resultado de validación
export interface ValidationResult {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

export interface ValidationError {
  field: string;
  message: string;
  code: string;
}

export interface ValidationWarning {
  field: string;
  message: string;
  suggestion?: string;
}

// Perfil de seguridad base
export interface SecurityProfileBase {
  name: string;
  q_origin_key?: string;
  uuid?: string;
  comment?: string;
  visibility?: 'enable' | 'disable';
  color?: number;
}

// Perfil de Antivirus
export interface AntivirusProfile extends SecurityProfileBase {
  inspection_mode?: 'proxy' | 'flow';
  ftgd_analytics?: 'disable' | 'suspicious' | 'everything';
  av_block_log?: 'enable' | 'disable';
  av_virus_log?: 'enable' | 'disable';
  av_quarantine?: 'enable' | 'disable';
  av_quarantine_expiry?: number;
  av_quarantine_log?: 'enable' | 'disable';
  http?: AvProtocolConfig;
  ftp?: AvProtocolConfig;
  imap?: AvProtocolConfig;
  pop3?: AvProtocolConfig;
  smtp?: AvProtocolConfig;
  mapi?: AvProtocolConfig;
  nntp?: AvProtocolConfig;
  cifs?: AvProtocolConfig;
  ssh?: AvProtocolConfig;
  analytics_max_upload?: number;
  analytics_db?: 'enable' | 'disable';
  analytics_bl?: 'enable' | 'disable';
  analytics_wl?: 'enable' | 'disable';
  scan_mode?: 'quick' | 'full';
  external_blocklist?: 'enable' | 'disable';
  external_blocklist_threat_tags?: string[];
}

export interface AvProtocolConfig {
  av_scan?: 'enable' | 'disable';
  av_block?: 'enable' | 'disable';
  av_quarantine?: 'enable' | 'disable';
  av_archive_log?: 'enable' | 'disable';
  options?: string;
}

// Perfil de Web Filter
export interface WebFilterProfile extends SecurityProfileBase {
  inspection_mode?: 'proxy' | 'flow';
  options?: string;
  https_replacemsg?: 'enable' | 'disable';
  ovrd_perm?: string;
  post_action?: 'normal' | 'block';
  web_content_log?: 'enable' | 'disable';
  web_filter_log?: 'enable' | 'disable';
  web_url_log?: 'enable' | 'disable';
  web_invalid_domain_log?: 'enable' | 'disable';
  web_ftgd_err_log?: 'enable' | 'disable';
  web_ftgd_quota_usage?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  web_filter_cookie?: 'enable' | 'disable';
  web_filter_cookie_removal?: 'enable' | 'disable';
  log_all_url?: 'enable' | 'disable';
  ftgd_wf?: FtgdWfConfig;
  ftgd_local_categories?: FtgdLocalCategory[];
  ftgd_local_rating?: FtgdLocalRating[];
  override?: WebFilterOverride[];
}

export interface FtgdWfConfig {
  options?: string;
  exempt_quota?: string;
  max_quota_timeout?: number;
  rate_crl_urls?: 'enable' | 'disable';
  rate_css_urls?: 'enable' | 'disable';
  rate_image_urls?: 'enable' | 'disable';
  rate_javascript_urls?: 'enable' | 'disable';
  filters?: FtgdFilter[];
}

export interface FtgdFilter {
  id: number;
  category: number;
  action: 'allow' | 'block' | 'monitor' | 'authenticate' | 'warning';
  log?: 'enable' | 'disable';
  override_replacemsg?: string;
  warn_duration?: string;
  auth_usr_grp?: string[];
  quota?: string;
  quota_value?: number;
  quota_max?: number;
}

export interface FtgdLocalCategory {
  name: string;
  q_origin_key: string;
  desc?: string;
  id?: number;
}

export interface FtgdLocalRating {
  url: string;
  q_origin_key: string;
  rating?: number;
}

export interface WebFilterOverride {
  id: number;
  q_origin_key: string;
  scope: 'user' | 'ip' | 'ask';
  ip?: string;
  ip6?: string;
  user?: string;
  user_group?: string;
  old_profile?: string;
  new_profile?: string;
  expires?: string;
  initiator?: string;
}

// Perfil de IPS (Intrusion Prevention)
export interface IpsProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  ips_log?: 'enable' | 'disable';
  ips_packet_log?: 'enable' | 'disable';
  ips_packet_quota?: number;
  ips_packet_log_memory?: number;
  ips_packet_log_interval?: number;
  extended_log?: 'enable' | 'disable';
  scan_botnet_connections?: 'disable' | 'block' | 'monitor';
  entries?: IpsEntry[];
}

export interface IpsEntry {
  id: number;
  q_origin_key: string;
  rule?: number[];
  location?: string[];
  severity?: string[];
  protocol?: string[];
  os?: string[];
  application?: string[];
  cve?: string[];
  status?: 'enable' | 'disable';
  log?: 'enable' | 'disable';
  log_packet?: 'enable' | 'disable';
  log_attack_context?: 'enable' | 'disable';
  action?: 'pass' | 'block' | 'reset' | 'default';
  rate_count?: number;
  rate_duration?: number;
  rate_mode?: 'periodical' | 'continuous';
  rate_track?: 'source' | 'destination' | 'source-destination';
  exempt_ip?: IpsExemptIp[];
  quarantine?: 'none' | 'attacker' | 'both' | 'interface';
  quarantine_expiry?: number;
  quarantine_log?: 'enable' | 'disable';
}

export interface IpsExemptIp {
  id: number;
  q_origin_key: string;
  src_ip?: string;
  dst_ip?: string;
}

// Perfil de Application Control
export interface ApplicationControlProfile extends SecurityProfileBase {
  comment?: string;
  replacemsg_group?: string;
  unknown_application_log?: 'enable' | 'disable';
  unknown_application_action?: 'pass' | 'block';
  deep_app_inspection?: 'enable' | 'disable';
  app_replacemsg?: 'enable' | 'disable';
  entries?: AppControlEntry[];
  control_default_network_services?: 'enable' | 'disable';
  default_network_services?: DefaultNetworkService[];
}

export interface AppControlEntry {
  id: number;
  q_origin_key: string;
  category?: number[];
  application?: number[];
  behavior?: string[];
  popularity?: string[];
  risk?: string[];
  technology?: string[];
  vendor?: string[];
  protocol?: string[];
  shaper?: string;
  shaper_reverse?: string;
  log?: 'enable' | 'disable';
  action?: 'pass' | 'block' | 'reset';
  rate_crl_urls?: 'enable' | 'disable';
  rate_css_urls?: 'enable' | 'disable';
  rate_image_urls?: 'enable' | 'disable';
  rate_javascript_urls?: 'enable' | 'disable';
  parameters?: AppControlParameter[];
}

export interface AppControlParameter {
  id: number;
  q_origin_key: string;
  member?: string;
  value?: string;
}

export interface DefaultNetworkService {
  id: number;
  q_origin_key: string;
  port?: number;
  services?: string;
}

// Perfil de DNS Filter
export interface DnsFilterProfile extends SecurityProfileBase {
  comment?: string;
  redirect_portal?: string;
  redirect_portal6?: string;
  block_action?: 'block' | 'redirect';
  block_botnet?: 'enable' | 'disable';
  log_all_domain?: 'enable' | 'disable';
  sdns_ftgd_err_log?: 'enable' | 'disable';
  sdns_domain_log?: 'enable' | 'disable';
  ftgd_dns?: FtgdDnsConfig;
  dns_translation?: DnsTranslation[];
  safe_search?: SafeSearchConfig;
  rpz?: RpzConfig;
  rpz_log?: 'enable' | 'disable';
  rpz_log_period?: number;
  extended_log?: 'enable' | 'disable';
}

export interface FtgdDnsConfig {
  options?: string;
  filters?: FtgdDnsFilter[];
}

export interface FtgdDnsFilter {
  id: number;
  category: number;
  action: 'allow' | 'block' | 'monitor';
  log?: 'enable' | 'disable';
}

export interface DnsTranslation {
  id: number;
  q_origin_key: string;
  src?: string;
  dst?: string;
  prefix?: string;
}

export interface SafeSearchConfig {
  options?: string;
}

export interface RpzConfig {
  options?: string;
}

// Perfil de File Filter
export interface FileFilterProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  log?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  scan_archive_contents?: 'enable' | 'disable';
  rules?: FileFilterRule[];
}

export interface FileFilterRule {
  name: string;
  q_origin_key: string;
  comment?: string;
  protocol?: string[];
  action?: 'log' | 'block';
  direction?: 'incoming' | 'outgoing' | 'any';
  password_protected?: 'any' | 'yes' | 'no';
  file_type?: string[];
  filter?: FileFilterCriteria[];
}

export interface FileFilterCriteria {
  filter: string;
  q_origin_key: string;
  action?: 'log' | 'block';
}

// Perfil de Email Filter
export interface EmailFilterProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  replacemsg_group?: string;
  spam_log?: 'enable' | 'disable';
  spam_log_fortiguard_response?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  imap?: EmailProtocolConfig;
  pop3?: EmailProtocolConfig;
  smtp?: EmailProtocolConfig;
  mapi?: EmailProtocolConfig;
  msn_hotmail?: EmailProtocolConfig;
  yahoo_mail?: EmailProtocolConfig;
  gmail?: EmailProtocolConfig;
  other_webmails?: EmailProtocolConfig;
  spam_bwl_table?: string;
  spam_bwl_status?: 'enable' | 'disable';
  spam_ipbwl_table?: string;
  spam_ipbwl_status?: 'enable' | 'disable';
  spam_mheader_table?: string;
  spam_mheader_status?: 'enable' | 'disable';
  spam_rbl_table?: string;
  spam_rbl_status?: 'enable' | 'disable';
  spam_filter?: 'enable' | 'disable';
  spam_bword_table?: string;
  spam_bword_status?: 'enable' | 'disable';
  spam_bword_threshold?: number;
  spam_bal_table?: string;
  spam_bal_status?: 'enable' | 'disable';
  spam_detect_header?: 'enable' | 'disable';
}

export interface EmailProtocolConfig {
  log?: 'enable' | 'disable';
  action?: 'tag' | 'discard' | 'pass';
  tag_type?: string;
  tag_msg?: string;
}

// Perfil de DLP (Data Leak Prevention)
export interface DlpProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  replacemsg_group?: string;
  rule?: DlpRule[];
  dlp_log?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  nac_quar_log?: 'enable' | 'disable';
}

export interface DlpRule {
  id: number;
  q_origin_key: string;
  name?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  protocol?: string[];
  filter_by?: string[];
  file_type?: string[];
  file_size?: DlpFileSize;
  action?: 'allow' | 'log-only' | 'block' | 'quarantine-ip' | 'ban' | 'ban-sender';
  expire_type?: 'none' | 'duration' | 'date';
  expire_duration?: string;
  expire_date?: string;
  status?: 'enable' | 'disable';
  inspection?: 'enable' | 'disable';
}

export interface DlpFileSize {
  greater_than?: number;
  less_than?: number;
}

// Perfil de VoIP
export interface VoipProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  sccp?: SccpConfig;
  sip?: SipConfig;
  mm?: MmConfig;
  sccp_log?: 'enable' | 'disable';
  sip_log?: 'enable' | 'disable';
  block_hid?: 'enable' | 'disable';
}

export interface SccpConfig {
  status?: 'enable' | 'disable';
  log_call_summary?: 'enable' | 'disable';
  log_violations?: 'enable' | 'disable';
  max_calls?: number;
}

export interface SipConfig {
  status?: 'enable' | 'disable';
  log_call_summary?: 'enable' | 'disable';
  log_violations?: 'enable' | 'disable';
  rtp?: 'enable' | 'disable';
  fix_contact?: 'enable' | 'disable';
  strict_register?: 'enable' | 'disable';
  open_contact_pinhole?: 'enable' | 'disable';
  open_record_route_pinhole?: 'enable' | 'disable';
  open_via_pinhole?: 'enable' | 'disable';
  max_calls?: number;
  max_dialogs?: number;
  subscribe_rate?: number;
  subscribe_rate_burst?: number;
  message_rate?: number;
  message_rate_burst?: number;
  notify_rate?: number;
  notify_rate_burst?: number;
  register_rate?: number;
  register_rate_burst?: number;
  invite_rate?: number;
  invite_rate_burst?: number;
  options_rate?: number;
  options_rate_burst?: number;
  ack_rate?: number;
  ack_rate_burst?: number;
  bye_rate?: number;
  bye_rate_burst?: number;
  cancel_rate?: number;
  cancel_rate_burst?: number;
  info_rate?: number;
  info_rate_burst?: number;
  prack_rate?: number;
  prack_rate_burst?: number;
  refer_rate?: number;
  refer_rate_burst?: number;
  update_rate?: number;
  update_rate_burst?: number;
  malformed_header_allow?: 'pass' | 'discard' | 'respond';
  malformed_header_call_id?: 'pass' | 'discard' | 'respond';
  malformed_header_contact?: 'pass' | 'discard' | 'respond';
  malformed_header_content_length?: 'pass' | 'discard' | 'respond';
  malformed_header_content_type?: 'pass' | 'discard' | 'respond';
  malformed_header_cseq?: 'pass' | 'discard' | 'respond';
  malformed_header_expires?: 'pass' | 'discard' | 'respond';
  malformed_header_from?: 'pass' | 'discard' | 'respond';
  malformed_header_max_forwards?: 'pass' | 'discard' | 'respond';
  malformed_header_p_asserted_identity?: 'pass' | 'discard' | 'respond';
  malformed_header_rack?: 'pass' | 'discard' | 'respond';
  malformed_header_record_route?: 'pass' | 'discard' | 'respond';
  malformed_header_route?: 'pass' | 'discard' | 'respond';
  malformed_header_rseq?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_a?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_b?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_c?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_i?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_k?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_m?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_o?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_r?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_s?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_t?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_v?: 'pass' | 'discard' | 'respond';
  malformed_header_sdp_z?: 'pass' | 'discard' | 'respond';
  malformed_header_to?: 'pass' | 'discard' | 'respond';
  malformed_header_via?: 'pass' | 'discard' | 'respond';
  malformed_header_warning?: 'pass' | 'discard' | 'respond';
  malformed_header_www_authenticate?: 'pass' | 'discard' | 'respond';
  strict_header_validation?: 'enable' | 'disable';
  block_cancel?: 'enable' | 'disable';
  block_info?: 'enable' | 'disable';
  block_invite?: 'enable' | 'disable';
  block_message?: 'enable' | 'disable';
  block_notify?: 'enable' | 'disable';
  block_options?: 'enable' | 'disable';
  block_prack?: 'enable' | 'disable';
  block_publish?: 'enable' | 'disable';
  block_refer?: 'enable' | 'disable';
  block_register?: 'enable' | 'disable';
  block_subscribe?: 'enable' | 'disable';
  block_update?: 'enable' | 'disable';
  msrp?: 'enable' | 'disable';
}

export interface MmConfig {
  status?: 'enable' | 'disable';
  log_call_summary?: 'enable' | 'disable';
  log_violations?: 'enable' | 'disable';
  max_calls?: number;
}

// Perfil de SSL/SSH Inspection (DPI)
export interface SslSshProfile extends SecurityProfileBase {
  comment?: string;
  ssl_anomalies_log?: 'enable' | 'disable';
  ssl_exemptions_log?: 'enable' | 'disable';
  ssl_negotiation_log?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  rpc_over_https?: 'enable' | 'disable';
  mapi_over_https?: 'enable' | 'disable';
  supported_alpn?: 'none' | 'http1-1' | 'http2' | 'http1-1-http2';
  use_ssl_server?: 'enable' | 'disable';
  caname?: string;
  untrusted_caname?: string;
  ssl?: SslInspectionConfig;
  https?: SslInspectionConfig;
  ftps?: SslInspectionConfig;
  imaps?: SslInspectionConfig;
  pop3s?: SslInspectionConfig;
  smtps?: SslInspectionConfig;
  ssh?: SshInspectionConfig;
  dot?: SslInspectionConfig;
  exemptions?: SslExemption[];
  server_cert?: SslServerCert[];
}

export interface SslInspectionConfig {
  status?: 'disable' | 'certificate-inspection' | 'deep-inspection';
  cert_validation_timeout?: 'allow' | 'ignore' | 'block';
  cert_validation_failure?: 'allow' | 'ignore' | 'block';
  invalid_server_cert?: 'allow' | 'block';
  revoked_server_cert?: 'allow' | 'block';
  expired_server_cert?: 'allow' | 'block';
  cert_validation_log?: 'enable' | 'disable';
  sni_server_cert_check?: 'enable' | 'strict' | 'disable';
  untrusted_cert?: 'allow' | 'block';
  unsupported_ssl_cipher?: 'allow' | 'block';
  unsupported_ssl_negotiation?: 'allow' | 'block';
  client_cert_request?: 'bypass' | 'inspect' | 'block';
  client_certificate?: 'bypass' | 'inspect' | 'block';
  unsupported_ssl_version?: 'allow' | 'block';
  invalid_ssl_version?: 'allow' | 'block';
  expired_ssl_version?: 'allow' | 'block';
  revoked_ssl_version?: 'allow' | 'block';
  unsupported_ssl_version_log?: 'enable' | 'disable';
  unknown_ssl_version?: 'allow' | 'block';
  ssl_negotiation_log?: 'enable' | 'disable';
  ssl_min_ver?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_max_ver?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_min_proto_ver?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_max_proto_ver?: 'ssl-3.0' | 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
}

export interface SshInspectionConfig {
  status?: 'disable' | 'deep-inspection';
  ssh_policy_check?: 'disable' | 'ssh' | 'fingerprint';
  ssh_algorithm?: 'compatible' | 'high-encryption';
  unsupported_version?: 'bypass' | 'block';
}

export interface SslExemption {
  id: number;
  q_origin_key: string;
  type?: 'fortiguard-category' | 'address' | 'address6' | 'wildcard-fqdn' | 'regex' | 'certificate';
  fortiguard_category?: number[];
  address?: string[];
  address6?: string[];
  wildcard_fqdn?: string[];
  regex?: string[];
  certificate?: string[];
  ssl_exemption_ip?: string;
  ssl_exemption_reversed?: number;
  comment?: string;
}

export interface SslServerCert {
  name: string;
  q_origin_key: string;
  cert?: string;
  ssl_other_server?: 'allow' | 'block';
  ssl_server_cert_log?: 'enable' | 'disable';
  ip?: string;
  https_client_cert_request?: 'bypass' | 'inspect' | 'block';
}

// Perfil de Video Filter
export interface VideoFilterProfile extends SecurityProfileBase {
  comment?: string;
  replacemsg_group?: string;
  log?: 'enable' | 'disable';
  extended_log?: 'enable' | 'disable';
  youtube?: YoutubeFilterConfig;
  vimeo?: VimeoFilterConfig;
  dailygifme?: DailygifmeFilterConfig;
  metacafe?: MetacafeFilterConfig;
  dailymotion?: DailymotionFilterConfig;
}

export interface YoutubeFilterConfig {
  filter_mode?: 'disable' | 'category' | 'channel';
  filter_type?: 'whitelist' | 'blacklist';
  category_others?: 'allow' | 'block';
  log?: 'enable' | 'disable';
  channel_status?: 'disable' | 'whitelist' | 'blacklist';
  channel_filter?: YoutubeChannelFilter[];
}

export interface YoutubeChannelFilter {
  name: string;
  q_origin_key: string;
  channel_id?: string;
  comment?: string;
}

export interface VimeoFilterConfig {
  filter_mode?: 'disable' | 'category';
  filter_type?: 'whitelist' | 'blacklist';
  category_others?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

export interface DailygifmeFilterConfig {
  filter_mode?: 'disable' | 'category';
  filter_type?: 'whitelist' | 'blacklist';
  category_others?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

export interface MetacafeFilterConfig {
  filter_mode?: 'disable' | 'category';
  filter_type?: 'whitelist' | 'blacklist';
  category_others?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

export interface DailymotionFilterConfig {
  filter_mode?: 'disable' | 'category';
  filter_type?: 'whitelist' | 'blacklist';
  category_others?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

// Perfil de ICAP
export interface IcapProfile extends SecurityProfileBase {
  comment?: string;
  icap_headers?: IcapHeader[];
  icap_log?: 'enable' | 'disable';
  preview?: 'enable' | 'disable';
  preview_data_length?: number;
  request?: 'enable' | 'disable';
  request_failure?: 'error' | 'bypass';
  request_path?: string;
  request_server?: string;
  response?: 'enable' | 'disable';
  response_failure?: 'error' | 'bypass';
  response_path?: string;
  response_server?: string;
  send_client_ip?: 'enable' | 'disable';
  send_client_port?: 'enable' | 'disable';
  send_http_traversal?: 'enable' | 'disable';
  send_https_decrypted?: 'enable' | 'disable';
  respmod_default_action?: 'forward' | 'bypass';
  reqmod_default_action?: 'forward' | 'bypass';
  respmod_forward_rules?: RespmodForwardRule[];
  reqmod_forward_rules?: ReqmodForwardRule[];
  strip_encoding?: 'enable' | 'disable';
}

export interface IcapHeader {
  id: number;
  q_origin_key: string;
  name?: string;
  content?: string;
  base64_encoding?: 'enable' | 'disable';
}

export interface RespmodForwardRule {
  name: string;
  q_origin_key: string;
  host?: string;
  action?: 'forward' | 'bypass';
  http_resp_status_code?: number[];
}

export interface ReqmodForwardRule {
  name: string;
  q_origin_key: string;
  host?: string;
  action?: 'forward' | 'bypass';
  http_resp_status_code?: number[];
}

// Perfil de WAF (Web Application Firewall)
export interface WafProfile extends SecurityProfileBase {
  comment?: string;
  extended_log?: 'enable' | 'disable';
  signature?: WafSignatureConfig;
  main_class?: WafMainClassConfig;
  sub_class?: WafSubClassConfig;
  url_access?: WafUrlAccess[];
  cookie_replay?: 'enable' | 'disable';
}

export interface WafSignatureConfig {
  credit_card_detection_threshold?: number;
  custom_signature?: WafCustomSignature[];
  disabled_signature?: string[];
  disabled_sub_class?: string[];
}

export interface WafCustomSignature {
  name: string;
  q_origin_key: string;
  action?: 'allow' | 'block' | 'monitor';
  log?: 'enable' | 'disable';
  severity?: 'low' | 'medium' | 'high';
  status?: 'enable' | 'disable';
}

export interface WafMainClassConfig {
  allow_class?: string[];
  block_class?: string[];
  log_class?: string[];
}

export interface WafSubClassConfig {
  action?: 'allow' | 'block' | 'monitor';
  log?: 'enable' | 'disable';
  severity?: 'low' | 'medium' | 'high';
  status?: 'enable' | 'disable';
}

export interface WafUrlAccess {
  id: number;
  q_origin_key: string;
  access_pattern?: WafAccessPattern[];
  action?: 'allow' | 'block' | 'bypass' | 'authenticate';
  address?: string;
  log?: 'enable' | 'disable';
  severity?: 'low' | 'medium' | 'high';
}

export interface WafAccessPattern {
  id: number;
  q_origin_key: string;
  negate?: 'enable' | 'disable';
  pattern?: string;
  regex?: 'enable' | 'disable';
  srcaddr?: string;
}

// Perfil de Inline CASB
export interface InlineCasbProfile extends SecurityProfileBase {
  comment?: string;
  saas_application?: CasbSaasApplication[];
}

export interface CasbSaasApplication {
  name: string;
  q_origin_key: string;
  status?: 'enable' | 'disable';
  default_action?: 'allow' | 'block' | 'log-only';
  safe_search?: 'enable' | 'disable';
  log?: 'enable' | 'disable';
  custom_control?: CasbCustomControl[];
  control_options?: CasbControlOptions;
}

export interface CasbCustomControl {
  name: string;
  q_origin_key: string;
  match?: CasbMatch[];
  action?: 'allow' | 'block' | 'log-only';
  log?: 'enable' | 'disable';
  status?: 'enable' | 'disable';
}

export interface CasbMatch {
  id: number;
  q_origin_key: string;
  tenant_extraction?: 'enable' | 'disable';
  tenant_extraction_key?: string;
  tenant_extraction_jq?: string;
  tenant_extraction_regexp?: string;
  header_name?: string;
  header_value?: string;
  domain?: string;
  path?: string;
  tenant?: CasbTenant[];
}

export interface CasbTenant {
  name: string;
  q_origin_key: string;
  attribute_name?: string;
  attribute_match_pattern?: 'exact' | 'substring' | 'regexp';
  attribute_value?: string;
  action?: 'allow' | 'block' | 'log-only';
}

export interface CasbControlOptions {
  log?: 'enable' | 'disable';
  safe_search?: 'enable' | 'disable';
  utm_bypass?: string[];
}

// Firewall Policy
export interface FirewallPolicy {
  policyid: number;
  q_origin_key: string;
  name?: string;
  uuid?: string;
  srcintf?: FirewallInterface[];
  dstintf?: FirewallInterface[];
  srcaddr?: FirewallAddress[];
  dstaddr?: FirewallAddress[];
  action?: 'accept' | 'deny' | 'ipsec';
  firewall_master_policies?: string;
  status?: 'enable' | 'disable';
  comments?: string;
  users?: FirewallUser[];
  groups?: FirewallGroup[];
  schedule?: string;
  service?: FirewallService[];
  tos?: string;
  tos_mask?: string;
  tos_negate?: 'enable' | 'disable';
  anti_replay?: 'enable' | 'disable';
  tcp_session_without_syn?: 'enable' | 'disable';
  geoip_anycast?: 'enable' | 'disable';
  geoip_match?: 'physical-location' | 'registered-location';
  dynamic_shaping?: 'enable' | 'disable';
  passive_wan_health_measurement?: 'enable' | 'disable';
  utm_status?: 'enable' | 'disable';
  inspection_mode?: 'proxy' | 'flow';
  http_policy_redirect?: 'enable' | 'disable';
  ssh_policy_redirect?: 'enable' | 'disable';
  webproxy_profile?: string;
  webproxy_forward_server?: string;
  logtraffic?: 'all' | 'utm' | 'disable';
  logtraffic_start?: 'enable' | 'disable';
  capture_packet?: 'enable' | 'disable';
  auto_asic_offload?: 'enable' | 'disable';
  wanopt?: 'enable' | 'disable';
  wanopt_profile?: string;
  webcache?: 'enable' | 'disable';
  webcache_https?: 'enable' | 'disable';
  session_ttl?: string;
  vlan_cos_fwd?: number;
  vlan_cos_rev?: number;
  wccp?: 'enable' | 'disable';
  nat?: 'enable' | 'disable';
  nat46?: 'enable' | 'disable';
  nat64?: 'enable' | 'disable';
  fixedport?: 'enable' | 'disable';
  ippool?: 'enable' | 'disable';
  poolname?: string[];
  poolname6?: string[];
  permit_any_host?: 'enable' | 'disable';
  permit_stun_host?: 'enable' | 'disable';
  src_vendor_mac?: string[];
  rtp_nat?: 'enable' | 'disable';
  preserve_src_port?: 'enable' | 'disable';
  load_balance?: 'enable' | 'disable';
  identity_based_route?: string;
  block_notification?: 'enable' | 'disable';
  custom_log_fields?: FirewallCustomLogField[];
  replacemsg_override_group?: string;
  srcaddr_negate?: 'enable' | 'disable';
  dstaddr_negate?: 'enable' | 'disable';
  service_negate?: 'enable' | 'disable';
  internet_service?: 'enable' | 'disable';
  internet_service_name?: string[];
  internet_service_id?: number[];
  internet_service_group?: string[];
  internet_service_custom?: string[];
  internet_service_custom_group?: string[];
  internet_service_src?: 'enable' | 'disable';
  internet_service_src_name?: string[];
  internet_service_src_id?: number[];
  internet_service_src_group?: string[];
  internet_service_src_custom?: string[];
  internet_service_src_custom_group?: string[];
  internet_service6?: 'enable' | 'disable';
  internet_service6_name?: string[];
  internet_service6_group?: string[];
  internet_service6_custom?: string[];
  internet_service6_src?: 'enable' | 'disable';
  internet_service6_src_name?: string[];
  internet_service6_src_group?: string[];
  internet_service6_src_custom?: string[];
  reputation_minimum?: number;
  reputation_direction?: 'source' | 'destination' | 'both';
  src_vendor_mac_negate?: 'enable' | 'disable';
  rtp_addr?: string;
  learning_mode?: 'enable' | 'disable';
  src_uuid?: string;
  dst_uuid?: string;
  service_uuid?: string;
  internet_service_src_negate?: 'enable' | 'disable';
  internet_service_negate?: 'enable' | 'disable';
  internet_service6_src_negate?: 'enable' | 'disable';
  internet_service6_negate?: 'enable' | 'disable';
  timeout_send_rst?: 'enable' | 'disable';
  ssl_ssh_profile?: string;
  dsri?: 'enable' | 'disable';
  radius_mac_auth_bypass?: 'enable' | 'disable';
  delay_tcp_npu_session?: 'enable' | 'disable';
  vlan_filter?: string;
  sgt_check?: 'enable' | 'disable';
  sgt?: string[];
  sgt_negate?: 'enable' | 'disable';
  profile_protocol_options?: string;
  av_profile?: string;
  webfilter_profile?: string;
  dnsfilter_profile?: string;
  ips_sensor?: string;
  application_list?: string;
  voip_profile?: string;
  icap_profile?: string;
  cifs_profile?: string;
  videofilter_profile?: string;
  waf_profile?: string;
  ssh_filter_profile?: string;
  profile_group?: string;
  natinbound?: 'enable' | 'disable';
  natoutbound?: 'enable' | 'disable';
  wsso?: 'enable' | 'disable';
  match_vip?: 'enable' | 'disable';
  match_vip_only?: 'enable' | 'disable';
  diffserv_copy?: 'enable' | 'disable';
  diffserv_forward?: string;
  diffserv_reverse?: string;
  diffservcode_forward?: string;
  diffservcode_rev?: string;
  tcp_mss_sender?: number;
  tcp_mss_receiver?: number;
  comments_x?: string;
  label?: string;
  global_label?: string;
  email_collect?: 'enable' | 'disable';
  email_collection_server?: string;
  dlp_profile?: string;
  dlp_sensor?: string;
  file_filter_profile?: string;
  casb_profile?: string;
  virtual_patch_profile?: string;
  cgn_log_server_grp?: string;
  policy_offload?: 'enable' | 'disable';
  cgn_session_quota?: number;
  cgn_resource_quota?: number;
  cgn_eif?: 'enable' | 'disable';
  cgn_eim?: 'enable' | 'disable';
  policy_path?: string;
  trans_policy?: string;
  fec?: 'enable' | 'disable';
  wanopt_detection?: 'active' | 'passive' | 'off';
  wanopt_passive_opt?: 'default' | 'transparent' | 'non-transparent';
  wanopt_profile_type?: 'single' | 'multiple';
  wanopt_peer?: string;
}

export interface FirewallInterface {
  name: string;
  q_origin_key: string;
}

export interface FirewallAddress {
  name: string;
  q_origin_key: string;
}

export interface FirewallUser {
  name: string;
  q_origin_key: string;
}

export interface FirewallGroup {
  name: string;
  q_origin_key: string;
}

export interface FirewallService {
  name: string;
  q_origin_key: string;
}

export interface FirewallCustomLogField {
  field_id: string;
  q_origin_key: string;
}

// Address Objects
export interface FirewallAddressObject {
  name: string;
  q_origin_key: string;
  uuid?: string;
  type?: 'ipmask' | 'iprange' | 'fqdn' | 'wildcard' | 'geography' | 'wildcard-fqdn' | 'mac' | 'interface-subnet' | 'dynamic';
  subnet?: string;
  macaddr?: MacAddress[];
  country?: string;
  cache_ttl?: number;
  sdn?: string;
  fsso_group?: string[];
  interface?: string;
  obj_tag?: string;
  obj_type?: 'ip' | 'mac';
  tag_detection_level?: string;
  tag_type?: string;
  comment?: string;
  associated_interface?: string;
  color?: number;
  filter?: string;
  sdn_addr_type?: 'private' | 'public';
  node_ip_only?: 'enable' | 'disable';
  obj_id?: string;
  list?: AddressListItem[];
  tagging?: AddressTagging[];
  allow_routing?: 'enable' | 'disable';
  fabric_object?: 'enable' | 'disable';
  start_ip?: string;
  end_ip?: string;
  start_mac?: string;
  end_mac?: string;
  fqdn?: string;
  wildcard_fqdn?: string;
  wildcard?: string;
}

export interface MacAddress {
  macaddr: string;
  q_origin_key: string;
}

export interface AddressListItem {
  ip: string;
  q_origin_key: string;
}

export interface AddressTagging {
  name: string;
  q_origin_key: string;
  category?: string;
  tags?: string[];
}

// Interfaces
export interface SystemInterface {
  name: string;
  q_origin_key: string;
  vdom?: string;
  vrf?: number;
  cli_conn_status?: number;
  mode?: 'static' | 'dhcp' | 'pppoe';
  dhcp_client_identifier?: string;
  distance?: number;
  priority?: number;
  dhcp_relay_interface_select_method?: 'auto' | 'sdwan' | 'specify';
  dhcp_relay_service?: 'enable' | 'disable';
  dhcp_relay_ip?: string;
  dhcp_relay_type?: 'regular' | 'ipsec';
  dhcp_relay_agent_option?: 'enable' | 'disable';
  management_ip?: string;
  ip?: string;
  allowaccess?: string;
  gw6?: string;
  dhcp6_prefix_delegation?: 'enable' | 'disable';
  dhcp6_prefix_hint?: string;
  gwd?: string;
  speed?: 'auto' | '10full' | '10half' | '100full' | '100half' | '1000full' | '1000half';
  status?: 'up' | 'down';
  netbios_forward?: 'enable' | 'disable';
  type?: 'physical' | 'vlan' | 'aggregate' | 'redundant' | 'tunnel' | 'vdom-link' | 'loopback' | 'switch' | 'hard-switch' | 'hdlc' | 'ppp' | 'ssl';
  netbios_ntlist?: string[];
  sflow_sampler?: 'enable' | 'disable';
  sflow_sample_rate?: number;
  sflow_poll_interval?: number;
  sflow_sample_direction?: 'tx' | 'rx' | 'both';
  sflow_collectors?: string[];
  stpforward?: 'enable' | 'disable';
  stpforward_mode?: 'rpl-all' | 'rpl-none' | 'rpl-bridge';
  subst?: string;
  substitute_dst_mac?: string;
  substitute_dhcp_gw?: 'enable' | 'disable';
  substitute_dhcp_gw_mac?: string;
  ping_serv_status?: number;
  ip_managed_by_fortiipam?: 'enable' | 'disable';
  ipmac?: 'enable' | 'disable';
  ident_accept?: 'enable' | 'disable';
  redirect?: 'enable' | 'disable';
  dedicated_to?: string;
  trust_ip_1?: string;
  trust_ip_2?: string;
  trust_ip_3?: string;
  trust_ip_4?: string;
  trust_ip_5?: string;
  trust_ip_6?: string;
  trust_ip_7?: string;
  trust_ip_8?: string;
  trust_ip_9?: string;
  trust_ip_10?: string;
  mtu_override?: 'enable' | 'disable';
  wccp?: 'enable' | 'disable';
  drop_overlapped_prefix?: 'enable' | 'disable';
  drop_fragment?: 'enable' | 'disable';
  interface?: string;
  vlanid?: number;
  role?: 'lan' | 'wan' | 'dmz' | 'undefined';
  snmp_index?: number;
  rgb?: string;
  virtual_interface?: 'enable' | 'disable';
  wif_id?: number;
  interface_identifier?: string;
  mac?: string;
  child_intf?: string[];
}

// VPN IPsec
export interface VpnIpsecPhase1 {
  name: string;
  q_origin_key: string;
  type?: 'static' | 'dynamic' | 'ddns';
  interface?: string;
  ike_version?: '1' | '2';
  local_gw?: string;
  local_gw6?: string;
  peertype?: 'any' | 'one' | 'dialup' | 'peer' | 'peergrp';
  peerid?: string;
  usrgrp?: string;
  peer?: string;
  peergrp?: string;
  mode?: 'main' | 'aggressive';
  mode_cfg?: 'enable' | 'disable';
  mode_cfg_allow_client_selector?: 'enable' | 'disable';
  assign_ip?: 'enable' | 'disable';
  assign_ip_from?: 'range' | 'usrgrp' | 'dhcp' | 'name';
  ipv4_start_ip?: string;
  ipv4_end_ip?: string;
  ipv4_netmask?: number;
  dhcp_ra_giaddr?: string;
  dhcp_ua_server?: string;
  assign_ip_type?: 'subnet' | 'interface-ip';
  assign_ip_type6?: 'subnet' | 'interface-ip';
  ipv6_start_ip?: string;
  ipv6_end_ip?: string;
  ipv6_prefix?: number;
  ip_delay_interval?: number;
  localid?: string;
  localid_type?: 'auto' | 'fqdn' | 'user-fqdn' | 'keyid';
  negotiation_timeout?: number;
  fragmentation?: 'enable' | 'disable';
  dpd?: 'disable' | 'on-idle' | 'on-demand';
  dpd_retrycount?: number;
  dpd_retryinterval?: string;
  forticlient_enforcement?: 'enable' | 'disable';
  comments?: string;
  npu_offload?: 'enable' | 'disable';
  send_cert_chain?: 'enable' | 'disable';
  dhgrp?: string[];
  suite_b?: 'disable' | 'suite-b-gcm-128' | 'suite-b-gcm-256';
  eap?: 'enable' | 'disable';
  eap_identity?: 'use-id-payload' | 'send-request';
  acct_verify?: 'enable' | 'disable';
  ppk?: 'disable' | 'allow' | 'require';
  ppk_secret?: string;
  ppk_identity?: string;
  wizard_type?: string;
  xauthtype?: 'disable' | 'client' | 'pap' | 'chap' | 'auto';
  reauth?: 'enable' | 'disable';
  authusr?: string;
  authpasswd?: string;
  group_authentication?: 'enable' | 'disable';
  group_authentication_secret?: string;
  authusrgrp?: string;
  mesh_selector_type?: 'disable' | 'subnet' | 'host';
  idle_timeout?: 'enable' | 'disable';
  idle_timeoutinterval?: number;
  ha_sync_esp_seqno?: 'enable' | 'disable';
  auto_discovery_sender?: 'enable' | 'disable';
  auto_discovery_receiver?: 'enable' | 'disable';
  auto_discovery_forwarder?: 'enable' | 'disable';
  encapsulation?: 'none' | 'gre' | 'vxlan';
  encapsulation_address?: 'ike' | 'ipv4' | 'ipv6';
  enforce_unique_id?: 'disable' | 'keep-new' | 'keep-old';
  cert_id_validation?: 'enable' | 'disable';
  auth_method?: 'psk' | 'signature' | 'signature-auth-enforcement';
  auth_method_remote?: 'psk' | 'signature';
  ikad_retrieve_interval?: number;
  passive_mode?: 'enable' | 'disable';
  exchange_interface_ip?: 'enable' | 'disable';
  exchange_ip_addr4?: string;
  exchange_ip_addr6?: string;
  aggregate_member?: 'enable' | 'disable';
  aggregate_weight?: number;
  mode_cfg_notice?: 'enable' | 'disable';
  unity_support?: 'enable' | 'disable';
  domain?: string;
  banner?: string;
  include_local_lan?: 'enable' | 'disable';
  ipv4_split_include?: string;
  ipv6_split_include?: string;
  split_include_service?: string;
  ipv4_name?: string;
  ipv6_name?: string;
  ip_mode?: 'range' | 'usrgrp' | 'dhcp' | 'name';
  ip6_mode?: 'range' | 'usrgrp' | 'dhcp' | 'name';
  exclusive_routing?: 'enable' | 'disable';
  reqid?: number;
  nattraversal?: 'enable' | 'disable' | 'forced';
  keylifesecs?: number;
  keylifekbs?: number;
  signature_algorithm?: string;
  keylife_type?: 'add' | 'both';
  rekey?: 'enable' | 'disable';
  localid_auto_update?: 'enable' | 'disable';
  localid_auto_update_interval?: number;
  cert_peer_username_validation?: 'enable' | 'disable';
  cert_peer_username_strip?: 'enable' | 'disable';
  cert_peer_username_delimiter?: string;
  cert_peer_username_max_num?: number;
  cert_peer_username_min_num?: number;
  cert_peer_username_order?: 'serial-number' | 'cn' | 'ou' | 'dn';
  cert_peer_username_validate?: 'enable' | 'disable';
  cert_trust_store?: 'enable' | 'disable';
  cert_trust_store_policy?: 'chain' | 'peer';
  cert_trust_store_group?: string;
  cert_trust_store_peer?: string;
  cert_trust_store_ca?: string;
  cert_trust_store_ocsp?: string;
  cert_trust_store_crl?: string;
  cert_trust_store_crl_strict?: 'enable' | 'disable';
  cert_trust_store_crl_verify?: 'enable' | 'disable';
  cert_trust_store_crl_check?: 'enable' | 'disable';
  cert_trust_store_crl_check_interval?: number;
  cert_trust_store_crl_update_interval?: number;
}

// ZTNA
export interface ZtnaAccessProxy {
  name: string;
  q_origin_key: string;
  uuid?: string;
  service?: ZtnaService[];
  empty_cert_action?: 'block' | 'accept';
  user_cert_ca?: string[];
  log_block?: 'enable' | 'disable';
  auth_portal?: 'enable' | 'disable';
  auth_rules?: ZtnaAuthRule[];
  client_cert?: 'enable' | 'disable';
  vip?: string;
  vip6?: string;
  api_gateway?: ZtnaApiGateway[];
  api_gateway6?: ZtnaApiGateway6[];
}

export interface ZtnaService {
  name: string;
  q_origin_key: string;
  service?: string;
  original_destination?: 'enable' | 'disable';
  ssl_algorithm?: 'high' | 'medium' | 'low';
  destination_port?: string;
  mappedport?: string;
  color?: number;
}

export interface ZtnaAuthRule {
  id: number;
  q_origin_key: string;
  status?: 'enable' | 'disable';
  match_host?: string;
  src_addr?: string[];
  src_addr6?: string[];
  users?: string[];
  groups?: string[];
}

export interface ZtnaApiGateway {
  id: number;
  q_origin_key: string;
  url_map?: string;
  service?: string;
  ldb_method?: 'static' | 'round-robin' | 'weighted' | 'first-alive' | 'http-host';
  url_map_type?: 'sub-string' | 'wildcard' | 'regex';
  http_cookie_domain_from_host?: 'disable' | 'insert' | 'replace';
  http_cookie_domain?: string;
  http_cookie_path?: string;
  http_cookie_generation?: number;
  http_cookie_age?: number;
  http_cookie_share?: 'disable' | 'same-ip';
  https_cookie_secure?: 'disable' | 'enable';
  http_cookie_same_site?: 'disable' | 'lax' | 'strict';
  http_multiplex?: 'enable' | 'disable';
  http_multiplex_max_concurrent_request?: number;
  http_multiplex_max_request_size?: number;
  http_supported_max_version?: 'http1' | 'http2';
  http2?: 'enable' | 'disable';
  http3?: 'enable' | 'disable';
  ssl_mode?: 'https' | 'http';
  ssl_certificate?: string;
  ssl_dh_bits?: '768' | '1024' | '1536' | '2048' | '3072' | '4096';
  ssl_algorithm?: 'high' | 'medium' | 'low';
  ssl_cipher_suites?: ZtnaSslCipherSuite[];
  ssl_min_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_max_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_renegotiation?: 'enable' | 'disable';
  realservers?: ZtnaRealServer[];
  persistence?: 'none' | 'http-cookie';
  nat?: 'enable' | 'disable';
  nat46?: 'enable' | 'disable';
  nat64?: 'enable' | 'disable';
  color?: number;
}

export interface ZtnaSslCipherSuite {
  priority: number;
  q_origin_key: string;
  cipher?: string;
  versions?: string;
}

export interface ZtnaRealServer {
  id: number;
  q_origin_key: string;
  address?: string;
  ip?: string;
  port?: number;
  status?: 'active' | 'standby' | 'disable';
  weight?: number;
  healthcheck?: 'enable' | 'disable';
  holddown_interval?: string;
  ssh_client_cert?: 'enable' | 'disable';
  ssh_client_cert_auth?: 'enable' | 'disable';
  ssh_replace_msg?: 'enable' | 'disable';
}

export interface ZtnaApiGateway6 {
  id: number;
  q_origin_key: string;
  url_map?: string;
  service?: string;
  ldb_method?: 'static' | 'round-robin' | 'weighted' | 'first-alive' | 'http-host';
  url_map_type?: 'sub-string' | 'wildcard' | 'regex';
  http_cookie_domain_from_host?: 'disable' | 'insert' | 'replace';
  http_cookie_domain?: string;
  http_cookie_path?: string;
  http_cookie_generation?: number;
  http_cookie_age?: number;
  http_cookie_share?: 'disable' | 'same-ip';
  https_cookie_secure?: 'disable' | 'enable';
  http_cookie_same_site?: 'disable' | 'lax' | 'strict';
  http_multiplex?: 'enable' | 'disable';
  http_multiplex_max_concurrent_request?: number;
  http_multiplex_max_request_size?: number;
  http_supported_max_version?: 'http1' | 'http2';
  http2?: 'enable' | 'disable';
  http3?: 'enable' | 'disable';
  ssl_mode?: 'https' | 'http';
  ssl_certificate?: string;
  ssl_dh_bits?: '768' | '1024' | '1536' | '2048' | '3072' | '4096';
  ssl_algorithm?: 'high' | 'medium' | 'low';
  ssl_cipher_suites?: ZtnaSslCipherSuite[];
  ssl_min_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_max_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_renegotiation?: 'enable' | 'disable';
  realservers?: ZtnaRealServer6[];
  persistence?: 'none' | 'http-cookie';
  nat?: 'enable' | 'disable';
  nat46?: 'enable' | 'disable';
  nat64?: 'enable' | 'disable';
  color?: number;
}

export interface ZtnaRealServer6 {
  id: number;
  q_origin_key: string;
  address?: string;
  ip?: string;
  port?: number;
  status?: 'active' | 'standby' | 'disable';
  weight?: number;
  healthcheck?: 'enable' | 'disable';
  holddown_interval?: string;
  ssh_client_cert?: 'enable' | 'disable';
  ssh_client_cert_auth?: 'enable' | 'disable';
  ssh_replace_msg?: 'enable' | 'disable';
}

// Virtual Patch Profile
export interface VirtualPatchProfile extends SecurityProfileBase {
  comment?: string;
  log?: 'enable' | 'disable';
  override?: VirtualPatchOverride[];
}

export interface VirtualPatchOverride {
  id: number;
  q_origin_key: string;
  rule_id?: number;
  status?: 'enable' | 'disable';
  action?: 'allow' | 'block' | 'monitor';
  log?: 'enable' | 'disable';
}

// SSH Filter Profile
export interface SshFilterProfile extends SecurityProfileBase {
  comment?: string;
  default_command_log?: 'enable' | 'disable';
  file_filter?: SshFileFilterConfig;
  shell_commands?: SshShellCommand[];
}

export interface SshFileFilterConfig {
  log?: 'enable' | 'disable';
  scan_all_files?: 'enable' | 'disable';
}

export interface SshShellCommand {
  id: number;
  q_origin_key: string;
  command_pattern?: string;
  action?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

// CIFS Profile
export interface CifsProfile extends SecurityProfileBase {
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  file_filter?: CifsFileFilterConfig;
  server_credential_type?: 'none' | 'credentials' | 'credential-replication';
  server_keytab?: CifsServerKeytab[];
}

export interface CifsFileFilterConfig {
  log?: 'enable' | 'disable';
  scan_all_files?: 'enable' | 'disable';
}

export interface CifsServerKeytab {
  principal: string;
  q_origin_key: string;
  keytab?: string;
}

// SD-WAN
export interface SdwanZone {
  name: string;
  q_origin_key: string;
  service_sla_tie_break?: 'cfg-order' | 'fib-best-match' | 'input-device';
  minimum_sla_meet_members?: number;
  members?: SdwanZoneMember[];
}

export interface SdwanZoneMember {
  interface: string;
  q_origin_key: string;
  zone?: string;
  cost?: number;
  weight?: number;
  priority?: number;
  spare?: 'enable' | 'disable';
  mode?: 'sla' | 'priority' | 'load-balance';
  mode_hsla?: 'enable' | 'disable';
  role?: 'standalone' | 'primary' | 'secondary';
  sla?: string[];
  priority_increase?: number;
  priority6_increase?: number;
}

export interface SdwanService {
  id: number;
  q_origin_key: string;
  name?: string;
  mode?: 'auto' | 'manual';
  quality_link?: number;
  member?: number[];
  tos?: string;
  tos_mask?: string;
  sla?: SdwanServiceSla[];
  priority_members?: number[];
  status?: 'enable' | 'disable';
  gateway?: 'enable' | 'disable';
  default?: 'enable' | 'disable';
  sla_compare_method?: 'order' | 'number';
  input_device?: string[];
  input_device_negate?: 'enable' | 'disable';
  use_incoming_interface?: 'enable' | 'disable';
}

export interface SdwanServiceSla {
  id: number;
  q_origin_key: string;
  health_check?: string;
  sla_id?: number;
}

// HA (High Availability)
export interface HaConfig {
  group_id: number;
  group_name?: string;
  mode?: 'standalone' | 'a-p' | 'a-a';
  sync_packet_balance?: 'enable' | 'disable';
  password?: string;
  key?: string;
  hbdev?: string;
  session_sync_dev?: string;
  priority?: number;
  override?: 'enable' | 'disable';
  priority_adjust?: number;
  gratuitous_arps?: 'enable' | 'disable';
  arps?: number;
  arps_interval?: number;
  ha_mgmt_status?: 'enable' | 'disable';
  ha_mgmt_interfaces?: HaMgmtInterface[];
  monitor?: string[];
  pingserver_monitor_interface?: string[];
  pingserver_failover_threshold?: number;
  pingserver_slave_force_reset?: 'enable' | 'disable';
  pingserver_flip_timeout?: number;
  external?: 'enable' | 'disable';
  external_interfaces?: HaExternalInterface[];
  route_ttl?: number;
  route_wait?: number;
  route_hold?: number;
  multicast_ttl?: number;
  evpn_ttl?: number;
  unicast_hb?: 'enable' | 'disable';
  unicast_hb_peerip?: string;
  unicast_hb_netmask?: string;
  unicast_hb_peerip6?: string;
  unicast_hb_ip6_prefix?: number;
  unicast_peervdn?: string;
  multicast_hb?: 'enable' | 'disable';
  multicast_hb_dev?: string;
  multicast_hb_ip?: string;
  multicast_hb_ip6?: string;
  multicast_hb_port?: number;
  multicast_hb_interval?: number;
  multicast_hb_lost_threshold?: number;
  multicast_hb_security?: 'enable' | 'disable';
  multicast_hb_key?: string;
  ha_direct?: 'enable' | 'disable';
  memory_based_failover?: 'enable' | 'disable';
  memory_compatible_mode?: 'enable' | 'disable';
  memory_failover_threshold?: number;
  memory_failover_monitor_period?: number;
  memory_failover_sample_rate?: number;
  memory_failover_flush_timeout?: number;
  cpu_based_failover?: 'enable' | 'disable';
  cpu_failover_threshold?: number;
  cpu_failover_sample_rate?: number;
  cpu_failover_monitor_period?: number;
  disk_based_failover?: 'enable' | 'disable';
  disk_failover_threshold?: number;
  disk_failover_sample_rate?: number;
  disk_failover_monitor_period?: number;
  session_pickup?: 'enable' | 'disable';
  session_pickup_connectionless?: 'enable' | 'disable';
  session_pickup_expectation?: 'enable' | 'disable';
  session_pickup_nat?: 'enable' | 'disable';
  session_pickup_delay?: 'enable' | 'disable';
  link_failed_signal?: 'enable' | 'disable';
  uninterruptible_upgrade?: 'enable' | 'disable';
  standalone_mgmt_vdom?: 'enable' | 'disable';
  ha_uuid?: string;
  vcluster?: HaVcluster[];
  vcluster_status?: 'enable' | 'disable';
}

export interface HaMgmtInterface {
  id: number;
  q_origin_key: string;
  interface?: string;
  dst?: string;
  gateway?: string;
  gateway6?: string;
}

export interface HaExternalInterface {
  id: number;
  q_origin_key: string;
  interface?: string;
  role?: 'primary' | 'secondary';
}

export interface HaVcluster {
  vcluster_id: number;
  q_origin_key: string;
  override?: 'enable' | 'disable';
  priority?: number;
  vdom?: string[];
}

// VDOM
export interface Vdom {
  name: string;
  q_origin_key: string;
  short_name?: string;
  vcluster_id?: number;
  physical_interface?: string;
  description?: string;
  ngfw_mode?: 'profile-based' | 'policy-based';
  ssl_ssh_profile?: string;
  application_list?: string;
  ips_sensor?: string;
  av_profile?: string;
  webfilter_profile?: string;
  dnsfilter_profile?: string;
  dlp_profile?: string;
  spamfilter_profile?: string;
  dlp_sensor?: string;
  replacemsg_group?: string;
  capture_packet?: 'enable' | 'disable';
  metadata?: VdomMetadata[];
}

export interface VdomMetadata {
  name: string;
  q_origin_key: string;
  value?: string;
}

// Administrador
export interface SystemAdmin {
  name: string;
  q_origin_key: string;
  wildcard?: 'enable' | 'disable';
  remote_auth?: 'enable' | 'disable';
  remote_group?: string;
  password?: string;
  peer_auth?: 'enable' | 'disable';
  peer_group?: string;
  trusthost1?: string;
  trusthost2?: string;
  trusthost3?: string;
  trusthost4?: string;
  trusthost5?: string;
  trusthost6?: string;
  trusthost7?: string;
  trusthost8?: string;
  trusthost9?: string;
  trusthost10?: string;
  ip6_trusthost1?: string;
  ip6_trusthost2?: string;
  ip6_trusthost3?: string;
  ip6_trusthost4?: string;
  ip6_trusthost5?: string;
  ip6_trusthost6?: string;
  ip6_trusthost7?: string;
  ip6_trusthost8?: string;
  ip6_trusthost9?: string;
  ip6_trusthost10?: string;
  accprofile?: string;
  vdom?: string[];
  vdom_override?: 'enable' | 'disable';
  description?: string;
  force_password_change?: 'enable' | 'disable';
  gui_dashboard?: AdminGuiDashboard[];
  gui_global_menu_favorites?: string[];
  gui_vdom_menu_favorites?: string[];
  gui_new_feature_acknowledge?: string[];
}

export interface AdminGuiDashboard {
  id: number;
  q_origin_key: string;
  name?: string;
  vdom?: string;
  permanent?: 'enable' | 'disable';
  layout?: string;
  widget?: AdminWidget[];
}

export interface AdminWidget {
  id: number;
  q_origin_key: string;
  type?: string;
  x_pos?: number;
  y_pos?: number;
  width?: number;
  height?: number;
  interface?: string;
  region?: string;
  industry?: string;
  fabric_device?: string;
  title?: string;
  report_by?: string;
  time_frame?: string;
  sort_by?: string;
  sort_order?: string;
  sort_option?: string;
  filter?: string;
  hide_empty_items?: 'enable' | 'disable';
  max_log_cnt?: number;
  log_type?: string;
  status?: 'enable' | 'disable';
  border?: 'enable' | 'disable';
  style?: string;
  drill_down?: 'enable' | 'disable';
  devices?: string;
  users?: string;
  severity?: string;
  event?: string;
  custom_log_field?: string;
}

// Perfil de acceso
export interface SystemAccprofile {
  name: string;
  q_origin_key: string;
  description?: string;
  scope?: 'vdom' | 'global';
  secfabgrp?: 'none' | 'read' | 'read-write';
  ftviewgrp?: 'none' | 'read' | 'read-write';
  authgrp?: 'none' | 'read' | 'read-write';
  sysgrp?: 'none' | 'read' | 'read-write';
  netgrp?: 'none' | 'read' | 'read-write';
  loggrp?: 'none' | 'read' | 'read-write';
  fwgrp?: 'none' | 'read' | 'read-write';
  vpngrp?: 'none' | 'read' | 'read-write';
  utmgrp?: 'none' | 'read' | 'read-write';
  wanoptgrp?: 'none' | 'read' | 'read-write';
  wifi?: 'none' | 'read' | 'read-write';
  admintimeout?: number;
  admintimeout_override?: 'enable' | 'disable';
  system_diagnostics?: 'enable' | 'disable';
  system_configuration?: 'enable' | 'disable';
  fortiguard_configuration?: 'enable' | 'disable';
  update_configuration?: 'enable' | 'disable';
}

// Configuración de logging
export interface LogFortiguardSetting {
  status?: 'enable' | 'disable';
  upload_time?: string;
  upload_day?: string;
  upload_interval?: 'daily' | 'weekly' | 'monthly';
  reliable?: 'enable' | 'disable';
  priority?: 'low' | 'default' | 'high';
  max_log_rate?: number;
  enc_algorithm?: 'default' | 'high' | 'low';
  ssl_protocol?: 'sslv3' | 'tlsv1' | 'tlsv1-1' | 'tlsv1-2';
  interface?: string;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
}

export interface LogSyslogdSetting {
  status?: 'enable' | 'disable';
  server?: string;
  mode?: 'udp' | 'legacy-reliable' | 'reliable';
  port?: number;
  facility?: 'kernel' | 'user' | 'mail' | 'daemon' | 'auth' | 'syslog' | 'lpr' | 'news' | 'uucp' | 'cron' | 'authpriv' | 'ftp' | 'ntp' | 'audit' | 'alert' | 'clock' | 'local0' | 'local1' | 'local2' | 'local3' | 'local4' | 'local5' | 'local6' | 'local7';
  source_ip?: string;
  source_ip_interface?: string;
  format?: 'default' | 'csv' | 'cef';
  priority?: 'default' | 'low' | 'high';
  max_log_rate?: number;
  interface?: string;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
  certificate?: string;
  reliable?: 'enable' | 'disable';
  ssl_min_proto_version?: 'default' | 'SSLv3' | 'TLSv1' | 'TLSv1-1' | 'TLSv1-2';
}

// FortiGuard
export interface SystemFortiguard {
  protocol?: 'udp' | 'http' | 'https';
  port?: '53' | '80' | '8888' | '443';
  service_account_id?: string;
  load_balance_servers?: number;
  auto_join_forticloud?: 'enable' | 'disable';
  update_server_location?: 'any' | 'usa' | 'automatic';
  sandbox_region?: 'us' | 'eu' | 'global';
  sandbox_inline_scan?: 'enable' | 'disable';
  antispam_force_off?: 'enable' | 'disable';
  antispam_timeout?: number;
  antivirus_force_off?: 'enable' | 'disable';
  antivirus_timeout?: number;
  file_query_timeout?: number;
  file_query_force_off?: 'enable' | 'disable';
  outbreak_prevention_force_off?: 'enable' | 'disable';
  outbreak_prevention_timeout?: number;
  webfilter_force_off?: 'enable' | 'disable';
  webfilter_timeout?: number;
  videofilter_force_off?: 'enable' | 'disable';
  videofilter_timeout?: number;
  sdns_server_ip?: string;
  sdns_server_port?: number;
  source_ip?: string;
  source_ip_interface?: string;
  ddns_server_ip?: string;
  ddns_server_port?: number;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
  interface?: string;
}

// SNMP
export interface SystemSnmpSysinfo {
  status?: 'enable' | 'disable';
  engine_id?: string;
  description?: string;
  contact_info?: string;
  location?: string;
  trap_log?: 'enable' | 'disable';
  trap_high_cpu_threshold?: number;
  trap_low_memory_threshold?: number;
  trap_free_disk_limit?: number;
  trap_high_cpu_interval?: number;
  trap_low_memory_interval?: number;
}

export interface SystemSnmpCommunity {
  id: number;
  q_origin_key: number;
  name?: string;
  status?: 'enable' | 'disable';
  hosts?: SnmpHost[];
  hosts6?: SnmpHost6[];
  trap_v1_lport?: number;
  trap_v1_rport?: number;
  trap_v2c_lport?: number;
  trap_v2c_rport?: number;
  events?: string;
}

export interface SnmpHost {
  id: number;
  q_origin_key: number;
  ip?: string;
  source_ip?: string;
  interface?: string;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
  vdom?: string;
}

export interface SnmpHost6 {
  id: number;
  q_origin_key: number;
  ipv6?: string;
  source_ipv6?: string;
  interface?: string;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
  vdom?: string;
}

// DHCP Server
export interface SystemDhcpServer {
  id: number;
  q_origin_key: number;
  status?: 'enable' | 'disable';
  lease_time?: number;
  mac_acl_default_action?: 'assign' | 'block';
  forticlient_on_net_status?: 'enable' | 'disable';
  dns_service?: 'default' | 'specify' | 'local';
  dns_server1?: string;
  dns_server2?: string;
  dns_server3?: string;
  dns_server4?: string;
  wifi_ac_service?: 'specify' | 'local';
  wifi_ac1?: string;
  wifi_ac2?: string;
  wifi_ac3?: string;
  ntp_service?: 'default' | 'specify' | 'local';
  ntp_server1?: string;
  ntp_server2?: string;
  ntp_server3?: string;
  domain?: string;
  wins_server1?: string;
  wins_server2?: string;
  default_gateway?: string;
  next_server?: string;
  tftp_server?: string[];
  filename?: string;
  options?: DhcpOption[];
  ip_mode?: 'range' | 'usrgrp' | 'dhcp' | 'name';
  ip6_mode?: 'range' | 'usrgrp' | 'dhcp' | 'name';
  interface?: string;
  ip_range?: DhcpIpRange[];
  reserved_address?: DhcpReservedAddress[];
}

export interface DhcpOption {
  id: number;
  q_origin_key: number;
  code?: number;
  type?: 'hex' | 'string' | 'ip' | 'fqdn';
  value?: string;
  ip?: string;
}

export interface DhcpIpRange {
  id: number;
  q_origin_key: number;
  start_ip?: string;
  end_ip?: string;
  vci_match?: 'disable' | 'enable';
  vci_string?: string[];
  dhcp_lease_time?: number;
  uci_match?: 'disable' | 'enable';
  uci_string?: string[];
  exclude?: 'enable' | 'disable';
}

export interface DhcpReservedAddress {
  id: number;
  q_origin_key: number;
  type?: 'mac' | 'option82';
  ip?: string;
  mac?: string;
  remote_id?: string;
  circuit_id?: string;
  description?: string;
  action?: 'assign' | 'block' | 'reserved';
}

// Certificate
export interface VpnCertificateCa {
  name: string;
  q_origin_key: string;
  default_ca?: 'enable' | 'disable';
  ca?: string;
  range?: 'global' | 'vdom';
  source?: 'factory' | 'user' | 'bundle';
  auto_update_days?: number;
  auto_update_days_warning?: number;
  scep_url?: string;
  scep_password?: string;
  scep_ca_cert?: string;
  scep_cert_poll_interval?: number;
  source_ip?: string;
  source_ip_interface?: string;
  interface_select_method?: 'auto' | 'sdwan' | 'specify';
  interface?: string;
  last_updated?: number;
}

export interface VpnCertificateLocal {
  name: string;
  q_origin_key: string;
  password?: string;
  comments?: string;
  private_key?: string;
  certificate?: string;
  csr?: string;
  state?: 'pending' | 'verified' | 'expired';
  range?: 'global' | 'vdom';
  source?: 'factory' | 'user' | 'bundle';
  source_ip?: string;
  source_ip_interface?: string;
  acme_ca_url?: string;
  acme_domain?: string;
  acme_email?: string;
  acme_renew_window?: number;
  acme_rsa_key_size?: number;
  auto_generate?: 'enable' | 'disable';
  auto_generate_warning?: 'enable' | 'disable';
  acme_account_key?: string;
  acme_key_type?: 'rsa' | 'ecdsa';
  acme_curve?: 'prime256v1' | 'secp384r1' | 'secp521r1';
  acme_signature_alg?: 'sha256' | 'sha384' | 'sha512';
  acme_ca_chain?: string;
  eab_key_id?: string;
  eab_key_hmac?: string;
}

// Schedule
export interface FirewallScheduleRecurring {
  name: string;
  q_origin_key: string;
  start?: string;
  end?: string;
  day?: string[];
}

export interface FirewallScheduleOnetime {
  name: string;
  q_origin_key: string;
  start?: string;
  end?: string;
  expiration_days?: number;
  color?: number;
}

// Service
export interface FirewallServiceCustom {
  name: string;
  q_origin_key: string;
  uuid?: string;
  proxy?: 'enable' | 'disable';
  category?: string;
  protocol?: 'TCP/UDP/SCTP' | 'ICMP' | 'ICMP6' | 'IP' | 'HTTP' | 'FTP' | 'CONNECT' | 'SOCKS-TCP' | 'SOCKS-UDP' | 'ALL';
  helper?: string;
  iprange?: string;
  fqdn?: string;
  protocol_number?: number;
  icmpcode?: number;
  icmptype?: number;
  icmp6code?: number;
  icmp6type?: number;
  explicit_proxy?: 'enable' | 'disable';
  tcp_portrange?: string[];
  udp_portrange?: string[];
  sctp_portrange?: string[];
  session_ttl?: number;
  comment?: string;
  color?: number;
  visibility?: 'enable' | 'disable';
  app_service_type?: 'disable' | 'app-id' | 'app-category';
  app_category?: number[];
  application?: number[];
}

// User
export interface UserLocal {
  name: string;
  q_origin_key: string;
  status?: 'enable' | 'disable';
  type?: 'password' | 'radius' | 'tacacs+' | 'ldap' | 'fortitoken' | 'email' | 'sms' | 'two-factor' | 'certificate' | 'fsso' | 'fortitoken-cloud';
  passwd?: string;
  ldap_server?: string;
  radius_server?: string;
  tacacs+-server?: string;
  two_factor?: 'disable' | 'fortitoken' | 'email' | 'sms' | 'fortitoken-cloud';
  fortitoken?: string;
  email_to?: string;
  sms_server?: 'fortiguard' | 'custom';
  sms_custom_server?: string;
  sms_phone?: string;
  passwd_policy?: string;
  passwd_time?: string;
  authtimeout?: number;
  workstation?: string;
  auth_concurrent_override?: 'enable' | 'disable';
  auth_concurrent_value?: number;
  ppk_secret?: string;
  ppk_identity?: string;
  qkd_profile?: string;
  qkd_profile_allowed?: string;
  username_sensitivity?: 'disable' | 'enable';
  username_case_sensitivity?: 'disable' | 'enable';
}

export interface UserGroup {
  name: string;
  q_origin_key: string;
  group_type?: 'firewall' | 'fsso-service' | 'rsso' | 'guest';
  authtimeout?: number;
  auth_concurrent_override?: 'enable' | 'disable';
  auth_concurrent_value?: number;
  http_digest_realm?: string;
  sso_attribute_value?: string;
  member?: UserGroupMember[];
  match?: UserGroupMatch[];
  guest?: UserGroupGuest[];
}

export interface UserGroupMember {
  name: string;
  q_origin_key: string;
}

export interface UserGroupMatch {
  id: number;
  q_origin_key: number;
  server_name?: string;
  group_name?: string;
}

export interface UserGroupGuest {
  id: number;
  q_origin_key: number;
  user_id?: string;
  name?: string;
  password?: string;
  mobile_phone?: string;
  email?: string;
  company?: string;
  sponsor?: string;
  expiration?: string;
  comment?: string;
}

// Shaper
export interface FirewallShaperTraffic {
  name: string;
  q_origin_key: string;
  guaranteed_bandwidth?: number;
  maximum_bandwidth?: number;
  bandwidth_unit?: 'kbps' | 'mbps' | 'gbps';
  priority?: 'high' | 'medium-high' | 'medium' | 'medium-low' | 'low';
  per_policy?: 'disable' | 'enable';
  diffserv?: 'enable' | 'disable';
  diffservcode?: string;
  dscp_marking_method?: 'multi-stage' | 'static';
  exceed_bandwidth?: number;
  exceed_dscp_forward?: string;
  exceed_class_id?: number;
  guaranteed_dscp_forward?: string;
  guaranteed_class_id?: number;
  maximum_dscp_forward?: string;
  maximum_class_id?: number;
  overhead?: number;
}

export interface FirewallShaperPerIp {
  name: string;
  q_origin_key: string;
  maximum_bandwidth?: number;
  bandwidth_unit?: 'kbps' | 'mbps' | 'gbps';
  diffserv?: 'enable' | 'disable';
  diffservcode?: string;
  max_concurrent_session?: number;
  max_concurrent_tcp_session?: number;
  max_new_session_per_second?: number;
  max_new_tcp_session_per_second?: number;
  per_policy?: 'disable' | 'enable';
  overhead?: number;
}

// Profile Group
export interface FirewallProfileGroup {
  name: string;
  q_origin_key: string;
  comment?: string;
  profile_protocol_options?: string;
  ssl_ssh_profile?: string;
  av_profile?: string;
  webfilter_profile?: string;
  dnsfilter_profile?: string;
  ips_sensor?: string;
  application_list?: string;
  voip_profile?: string;
  icap_profile?: string;
  cifs_profile?: string;
  videofilter_profile?: string;
  waf_profile?: string;
  ssh_filter_profile?: string;
  file_filter_profile?: string;
  dlp_profile?: string;
  dlp_sensor?: string;
  casb_profile?: string;
  virtual_patch_profile?: string;
}

// Protocol Options
export interface FirewallProfileProtocolOptions {
  name: string;
  q_origin_key: string;
  comment?: string;
  feature_set?: 'flow' | 'proxy';
  options?: ProtocolOption[];
  oversize_log?: 'enable' | 'disable';
  switching_protocols_log?: 'enable' | 'disable';
  chunkedbypass?: 'enable' | 'disable';
  http?: HttpProtocolOptions;
  ftp?: FtpProtocolOptions;
  imap?: ImapProtocolOptions;
  pop3?: Pop3ProtocolOptions;
  smtp?: SmtpProtocolOptions;
  mapi?: MapiProtocolOptions;
  nntp?: NntpProtocolOptions;
  dns?: DnsProtocolOptions;
  ssh?: SshProtocolOptions;
  cifs?: CifsProtocolOptions;
  radius?: RadiusProtocolOptions;
}

export interface ProtocolOption {
  protocol: string;
  q_origin_key: string;
  action?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

export interface HttpProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  comfort_interval?: number;
  comfort_amount?: number;
  range_block?: 'enable' | 'disable';
  http_policy?: 'enable' | 'disable';
  strip_x_forwarded_for?: 'disable' | 'enable';
  post_lang?: 'jisx0208' | 'gb2312' | 'ksc5601' | 'big5' | 'rf2047';
  switching_protocols?: 'bypass' | 'block';
  http_proxy?: 'enable' | 'disable';
  http_inspection?: 'enable' | 'disable';
  http_inspection_mode?: 'single' | 'parallel';
  http_inspection_default_profile?: string;
  http_inspection_profile?: HttpInspectionProfile[];
}

export interface HttpInspectionProfile {
  name: string;
  q_origin_key: string;
  host?: string;
  path?: string;
  action?: 'allow' | 'block';
  log?: 'enable' | 'disable';
}

export interface FtpProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  comfort_interval?: number;
  comfort_amount?: number;
  inspect_all?: 'enable' | 'disable';
}

export interface ImapProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  inspect_all?: 'enable' | 'disable';
}

export interface Pop3ProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  inspect_all?: 'enable' | 'disable';
}

export interface SmtpProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  inspect_all?: 'enable' | 'disable';
}

export interface MapiProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
}

export interface NntpProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  inspect_all?: 'enable' | 'disable';
}

export interface DnsProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
}

export interface SshProtocolOptions {
  options?: string[];
  comfort_interval?: number;
  comfort_amount?: number;
}

export interface CifsProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
  options?: string[];
  comfort_interval?: number;
  comfort_amount?: number;
}

export interface RadiusProtocolOptions {
  ports?: number[];
  status?: 'enable' | 'disable';
}

// VIP (Virtual IP)
export interface FirewallVip {
  name: string;
  q_origin_key: string;
  uuid?: string;
  comment?: string;
  type?: 'static-nat' | 'load-balance' | 'server-load-balance' | 'dns-translation' | 'fqdn' | 'access-proxy';
  dns_mapping_ttl?: number;
  ldb_method?: 'static' | 'round-robin' | 'weighted' | 'least-session' | 'least-rtt' | 'first-alive' | 'http-host';
  extip?: string[];
  extaddr?: string[];
  nat44?: 'enable' | 'disable';
  nat46?: 'enable' | 'disable';
  add_nat46_route?: 'enable' | 'disable';
  ipv6_mappedip?: string;
  ipv6_mappedport?: number;
  extintf?: string;
  extport?: string;
  http_cookie_domain_from_host?: 'disable' | 'insert' | 'replace';
  http_cookie_domain?: string;
  http_cookie_path?: string;
  http_cookie_generation?: number;
  http_cookie_age?: number;
  http_cookie_share?: 'disable' | 'same-ip';
  https_cookie_secure?: 'disable' | 'enable';
  http_cookie_same_site?: 'disable' | 'lax' | 'strict';
  http_multiplex?: 'enable' | 'disable';
  http_multiplex_max_concurrent_request?: number;
  http_multiplex_max_request_size?: number;
  http_multiplex_ttl?: number;
  http_supported_max_version?: 'http1' | 'http2';
  http2?: 'enable' | 'disable';
  http3?: 'enable' | 'disable';
  http_ip_header?: 'enable' | 'disable';
  http_ip_header_name?: string;
  http_ip_header_alternative?: 'enable' | 'disable';
  http_ip_header_alternative_name?: string;
  http_host_mapping?: VipHttpHostMapping[];
  ssl_mode?: 'half' | 'full';
  ssl_certificate?: string;
  ssl_dh_bits?: '768' | '1024' | '1536' | '2048' | '3072' | '4096';
  ssl_algorithm?: 'high' | 'medium' | 'low';
  ssl_cipher_suites?: VipSslCipherSuite[];
  ssl_server_algorithm?: 'high' | 'medium' | 'low' | 'client' | 'client-high' | 'client-medium' | 'client-low';
  ssl_server_cipher_suites?: VipSslServerCipherSuite[];
  ssl_pfs?: 'require' | 'deny' | 'allow';
  ssl_min_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_max_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3';
  ssl_server_min_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3' | 'client';
  ssl_server_max_version?: 'tls-1.0' | 'tls-1.1' | 'tls-1.2' | 'tls-1.3' | 'client';
  ssl_accept_ffdhe_groups?: 'enable' | 'disable';
  ssl_client_renegotiation?: 'allow' | 'deny' | 'secure';
  ssl_client_session_state_type?: 'disable' | 'time' | 'count' | 'both';
  ssl_client_session_state_timeout?: number;
  ssl_client_session_state_max?: number;
  ssl_client_fallback?: 'enable' | 'disable';
  ssl_server_renegotiation?: 'enable' | 'disable';
  ssl_server_session_state_type?: 'disable' | 'time' | 'count' | 'both';
  ssl_server_session_state_timeout?: number;
  ssl_server_session_state_max?: number;
  ssl_http_location_conversion?: 'enable' | 'disable';
  ssl_http_match_host?: 'enable' | 'disable';
  ssl_hpkp?: 'disable' | 'report-only' | 'enforce';
  ssl_hpkp_primary?: string;
  ssl_hpkp_backup?: string;
  ssl_hpkp_age?: number;
  ssl_hpkp_report_uri?: string;
  ssl_hpkp_include_subdomains?: 'enable' | 'disable';
  ssl_hsts?: 'disable' | 'enable';
  ssl_hsts_age?: number;
  ssl_hsts_include_subdomains?: 'enable' | 'disable';
  monitor?: string[];
  color?: number;
  mappedip?: string[];
  mapped_addr?: string[];
  extaddr?: string[];
  portforward?: 'enable' | 'disable';
  protocol?: 'tcp' | 'udp' | 'sctp' | 'tcp-udp';
  extport?: string;
  mappedport?: string;
  gratuitous_arp_interval?: number;
  srcintf_filter?: string[];
  src_filter?: string[];
  service?: string[];
  service6?: string[];
  server_type?: 'http' | 'https' | 'imaps' | 'pop3s' | 'smtps' | 'ssl' | 'tcp' | 'udp' | 'ip';
  http_ip_header?: 'enable' | 'disable';
  http_ip_header_name?: string;
  http_ip_header_alternative?: 'enable' | 'disable';
  http_ip_header_alternative_name?: string;
  realservers?: VipRealServer[];
  persistence?: 'none' | 'http-cookie' | 'ssl-session-id';
  nat_source_vip?: 'enable' | 'disable';
  outlook_web_access?: 'enable' | 'disable';
  weblogic_server?: 'enable' | 'disable';
  websphere_server?: 'enable' | 'disable';
  ssl_renegotiation?: 'enable' | 'disable';
  dynamic_mapping?: VipDynamicMapping[];
}

export interface VipHttpHostMapping {
  id: number;
  q_origin_key: number;
  host_from?: string;
  host_to?: string;
}

export interface VipSslCipherSuite {
  priority: number;
  q_origin_key: string;
  cipher?: string;
  versions?: string;
}

export interface VipSslServerCipherSuite {
  priority: number;
  q_origin_key: string;
  cipher?: string;
  versions?: string;
}

export interface VipRealServer {
  id: number;
  q_origin_key: number;
  type?: 'ip' | 'address';
  address?: string;
  ip?: string;
  port?: number;
  status?: 'active' | 'standby' | 'disable';
  weight?: number;
  holddown_interval?: string;
  healthcheck?: 'enable' | 'disable';
  http_host?: string;
  translate_host?: 'enable' | 'disable';
  monitor?: string[];
}

export interface VipDynamicMapping {
  _scope?: VipDynamicMappingScope[];
  name?: string;
  q_origin_key: string;
  extip?: string[];
  mappedip?: string[];
  extport?: string;
  mappedport?: string;
}

export interface VipDynamicMappingScope {
  name: string;
  q_origin_key: string;
  vdom?: string;
}

// IP Pool
export interface FirewallIppool {
  name: string;
  q_origin_key: string;
  uuid?: string;
  type?: 'overload' | 'one-to-one' | 'fixed-port-range' | 'port-block-allocation';
  startip?: string;
  endip?: string;
  startport?: number;
  endport?: number;
  block_size?: number;
  num_blocks_per_user?: number;
  source_startip?: string;
  source_endip?: string;
  arp_intf?: string;
  arp_reply?: 'enable' | 'disable';
  associated_interface?: string;
  comments?: string;
  cgn_block_size?: number;
  cgn_client_endip?: string;
  cgn_client_startip?: string;
  cgn_fixedalloc?: 'enable' | 'disable';
  cgn_overload?: 'enable' | 'disable';
  cgn_port_end?: number;
  cgn_port_start?: number;
  cgn_spa?: 'enable' | 'disable';
  dynamic_mapping?: IppoolDynamicMapping[];
}

export interface IppoolDynamicMapping {
  _scope?: IppoolDynamicMappingScope[];
  endip?: string;
  startip?: string;
}

export interface IppoolDynamicMappingScope {
  name: string;
  q_origin_key: string;
  vdom?: string;
}

// Proxy Policy
export interface FirewallProxyPolicy {
  policyid: number;
  q_origin_key: string;
  uuid?: string;
  name?: string;
  proxy?: 'explicit-web' | 'transparent-web' | 'ftp' | 'ssh' | 'ssh-host-key' | 'access-proxy';
  srcintf?: ProxyInterface[];
  dstintf?: ProxyInterface[];
  srcaddr?: ProxyAddress[];
  dstaddr?: ProxyAddress[];
  ztna_device_ownership?: 'enable' | 'disable';
  ztna_ems_tag_check?: 'enable' | 'disable';
  ztna_policy_unmatched?: 'block' | 'exempt';
  ztna_geo_tag?: string[];
  internet_service?: 'enable' | 'disable';
  internet_service_name?: string[];
  internet_service_group?: string[];
  internet_service_custom?: string[];
  internet_service_custom_group?: string[];
  internet_service_negate?: 'enable' | 'disable';
  internet_service_src?: 'enable' | 'disable';
  internet_service_src_name?: string[];
  internet_service_src_group?: string[];
  internet_service_src_custom?: string[];
  internet_service_src_custom_group?: string[];
  internet_service_src_negate?: 'enable' | 'disable';
  internet_service6?: 'enable' | 'disable';
  internet_service6_name?: string[];
  internet_service6_group?: string[];
  internet_service6_custom?: string[];
  internet_service6_negate?: 'enable' | 'disable';
  internet_service6_src?: 'enable' | 'disable';
  internet_service6_src_name?: string[];
  internet_service6_src_group?: string[];
  internet_service6_src_custom?: string[];
  internet_service6_src_negate?: 'enable' | 'disable';
  ztna_ems_tag?: string[];
  ztna_tags_match_logic?: 'or' | 'and';
  device_ownership?: 'enable' | 'disable';
  srcaddr_negate?: 'enable' | 'disable';
  dstaddr_negate?: 'enable' | 'disable';
  service?: ProxyService[];
  service_negate?: 'enable' | 'disable';
  action?: 'accept' | 'deny';
  status?: 'enable' | 'disable';
  schedule?: string;
  logtraffic?: 'all' | 'utm' | 'disable';
  session_ttl?: string;
  srcaddr6?: ProxyAddress[];
  dstaddr6?: ProxyAddress[];
  groups?: ProxyGroup[];
  users?: ProxyUser[];
  http_tunnel_auth?: 'enable' | 'disable';
  ssh_policy_redirect?: 'enable' | 'disable';
  webproxy_forward_server?: string;
  webproxy_profile?: string;
  transparent?: 'enable' | 'disable';
  webcache?: 'enable' | 'disable';
  webcache_https?: 'enable' | 'disable';
  disclaimer?: 'enable' | 'disable';
  nat?: 'enable' | 'disable';
  nat46?: 'enable' | 'disable';
  nat64?: 'enable' | 'disable';
  nat_outgoing_vip?: 'enable' | 'disable';
  fixedport?: 'enable' | 'disable';
  ippool?: 'enable' | 'disable';
  poolname?: string[];
  poolname6?: string[];
  replacemsg_override_group?: string;
  log_http_transaction?: 'enable' | 'disable';
  log_http_transaction_scope?: 'all' | 'policy';
  label?: string;
  global_label?: string;
  comments?: string;
  scan_botnet_connections?: 'disable' | 'block' | 'monitor';
  diffserv_forward?: 'enable' | 'disable';
  diffserv_reverse?: 'enable' | 'disable';
  diffservcode_forward?: string;
  diffservcode_rev?: string;
  tcp_mss_sender?: number;
  tcp_mss_receiver?: number;
  comments_x?: string;
  utm_status?: 'enable' | 'disable';
  profile_type?: 'single' | 'group';
  profile_group?: string;
  profile_protocol_options?: string;
  av_profile?: string;
  webfilter_profile?: string;
  dnsfilter_profile?: string;
  emailfilter_profile?: string;
  dlp_profile?: string;
  file_filter_profile?: string;
  ips_sensor?: string;
  application_list?: string;
  ssh_filter_profile?: string;
  ssl_ssh_profile?: string;
  casb_profile?: string;
  virtual_patch_profile?: string;
  voip_profile?: string;
  icap_profile?: string;
  cifs_profile?: string;
  videofilter_profile?: string;
  waf_profile?: string;
  authentication?: 'enable' | 'disable';
  realm?: string;
  redirect_url?: string;
  sso_auth_method?: 'fsso' | 'rsso';
  agent_disabled_by_icap?: 'enable' | 'disable';
}

export interface ProxyInterface {
  name: string;
  q_origin_key: string;
}

export interface ProxyAddress {
  name: string;
  q_origin_key: string;
}

export interface ProxyService {
  name: string;
  q_origin_key: string;
}

export interface ProxyGroup {
  name: string;
  q_origin_key: string;
}

export interface ProxyUser {
  name: string;
  q_origin_key: string;
}

// Switch Controller
export interface SwitchControllerManagedSwitch {
  switch_id: string;
  q_origin_key: string;
  name?: string;
  description?: string;
  switch_profile?: string;
  access_profile?: string;
  fsw_wan1_peer?: string;
  fsw_wan1_admin?: 'enable' | 'disable';
  fsw_wan2_peer?: string;
  fsw_wan2_admin?: 'enable' | 'disable';
  poe_detection_type?: number;
  poe_lldp_detection?: 'enable' | 'disable';
  poe_pre_standard_detection?: 'enable' | 'disable';
  directly_connected?: number;
  version?: number;
  max_version?: number;
  dynamic_capability?: number;
  static_capability?: number;
  fsw_wan1_peer_port?: string;
  fsw_wan2_peer_port?: string;
  dynamically_discovered?: 'enable' | 'disable';
  type?: string;
  owner_vdom?: string;
  flow_identity?: string;
  stp_state?: 'enabled' | 'disabled';
  stp_root_guard?: 'enabled' | 'disabled';
  stp_bpdu_guard?: 'enabled' | 'disabled';
  stp_root_guard_timeout?: number;
  non_eap_frame_fwd?: 'enable' | 'disable';
  port?: SwitchControllerPort[];
  mirror?: SwitchControllerMirror[];
  static_mac?: SwitchControllerStaticMac[];
  vlan?: SwitchControllerVlan[];
  stp_settings?: SwitchControllerStpSettings;
  igmp_snooping?: SwitchControllerIgmpSnooping;
  mclag_igmp_snooping_aware?: 'enable' | 'disable';
  qos_drop_policy?: 'taildrop' | 'weighted-random-early-detection';
  qos_red_probability?: number;
}

export interface SwitchControllerPort {
  port_name: string;
  q_origin_key: string;
  port_owner?: string;
  switch_id?: string;
  speed?: 'auto' | '10full' | '10half' | '100full' | '100half' | '1000full' | '1000half' | '10000full';
  status?: 'up' | 'down';
  poe_status?: 'enable' | 'disable';
  poe_pre_standard?: 'enable' | 'disable';
  poe_standard?: '8023af' | '8023at' | '8023bt';
  poe_capable?: number;
  poe_port_power?: string;
  poe_port_priority?: 'critical-priority' | 'high-priority' | 'low-priority';
  poe_max_power?: number;
  poe_mode_bt_type?: 'type-1' | 'type-2' | 'type-3' | 'type-4';
  aggregate?: string;
  mirror?: 'enable' | 'disable';
  mirror_dst_port?: string;
  media_type?: 'copper' | 'fiber' | 'auto';
  port_security?: SwitchControllerPortSecurity;
  storm_control?: SwitchControllerStormControl;
  igmp_snooping?: 'enable' | 'disable';
  igmps_flood_reports?: 'enable' | 'disable';
  igmps_flood_traffic?: 'enable' | 'disable';
  stp_state?: 'enabled' | 'disabled';
  stp_root_guard?: 'enabled' | 'disabled';
  stp_bpdu_guard?: 'enabled' | 'disabled';
  stp_bpdu_guard_timeout?: number;
  edge_port?: 'enable' | 'disable';
  discard_mode?: 'none' | 'all-untagged' | 'all-tagged';
  packet_sampler?: 'enable' | 'disable';
  packet_sample_rate?: number;
  sflow_sampler?: 'enabled' | 'disabled';
  sflow_sample_rate?: number;
  sflow_counter_interval?: number;
  sample_direction?: 'tx' | 'rx' | 'both';
  security_mode?: 'none' | '802.1X' | '802.1X-mac-based';
  security_mac_auth_bypass?: 'enable' | 'disable';
  security_external_web?: string;
  security_external_web_style?: 'auto' | 'no-theme' | 'red' | 'blue' | 'green' | 'magenta' | 'cyan' | 'orange' | 'brown';
  security_replace_msg?: 'enable' | 'disable';
  security_groups?: string[];
  security_8021x_master?: string;
  port_security?: SwitchControllerPortSecurity;
  qos_policy?: string;
  qos_red_probability?: number;
  qos_drop_policy?: 'taildrop' | 'weighted-random-early-detection';
  dscp_map_override?: 'enable' | 'disable';
  dscp_map?: string;
  trust_dot1p_map?: string;
  trust_ip_dscp_map?: string;
  mac_learning?: 'enable' | 'disable';
  export_to?: string;
  export_tags?: string[];
  learning_limit?: number;
  learning_limit_action?: 'none' | 'shutdown' | 'drop';
  lldp_status?: 'enable' | 'disable';
  lldp_profile?: string;
  export_to_pool?: string;
  export_to_pool_flag?: number;
  description?: string;
  flow_control?: 'enable' | 'disable';
  ingress_cos?: 'disable' | 'cos0' | 'cos1' | 'cos2' | 'cos3' | 'cos4' | 'cos5' | 'cos6' | 'cos7';
  trunk?: 'enable' | 'disable';
  access_mode?: 'normal' | 'nac' | 'dynamic' | 'static';
}

export interface SwitchControllerPortSecurity {
  security_mode?: 'none' | '802.1X' | '802.1X-mac-based';
  port_security?: 'enable' | 'disable';
  auth_fail_vlan?: 'enable' | 'disable';
  auth_fail_vlan_id?: string;
  auth_fail_vlan_allow?: 'enable' | 'disable';
  eap_auto_untagged_vlans?: 'enable' | 'disable';
  authserver_timeout_vlan?: 'enable' | 'disable';
  authserver_timeout_vlan_id?: string;
  authserver_timeout_tagged?: 'enable' | 'disable';
  authserver_timeout_tagged_vlanid?: string;
  guest_vlan?: 'enable' | 'disable';
  guest_vlan_id?: string;
  guest_vlan_tagged?: 'enable' | 'disable';
  guest_vlan_tagged_vlanid?: string;
  mac_auth_bypass?: 'enable' | 'disable';
  allow_mac_move?: 'enable' | 'disable';
  guest_auth_delay?: number;
  framevid_apply?: 'enable' | 'disable';
  radius_timeout_overwrite?: 'enable' | 'disable';
  policy?: string;
  open_auth?: 'enable' | 'disable';
  eap_egress_tagged?: 'enable' | 'disable';
  mac_called_station_delimiter?: 'hyphen' | 'single-hyphen' | 'colon' | 'none';
  mac_calling_station_delimiter?: 'hyphen' | 'single-hyphen' | 'colon' | 'none';
  mac_case?: 'uppercase' | 'lowercase';
  mac_password_delimiter?: 'hyphen' | 'single-hyphen' | 'colon' | 'none';
  mac_username_delimiter?: 'hyphen' | 'single-hyphen' | 'colon' | 'none';
  mac_auth_bypass_username?: 'mac-address' | 'fixed';
  mac_auth_bypass_password?: 'mac-address' | 'fixed';
  dynamic_sort_subform?: 'sort-by-name' | 'sort-by-value';
}

export interface SwitchControllerStormControl {
  broadcast?: 'enable' | 'disable';
  unknown_multicast?: 'enable' | 'disable';
  unknown_unicast?: 'enable' | 'disable';
  broadcast_rate?: number;
  unknown_multicast_rate?: number;
  unknown_unicast_rate?: number;
}

export interface SwitchControllerMirror {
  name: string;
  q_origin_key: string;
  status?: 'active' | 'inactive';
  switching_packet?: 'enable' | 'disable';
  dst_port?: string;
  src_ingress?: string[];
  src_egress?: string[];
}

export interface SwitchControllerStaticMac {
  id: number;
  q_origin_key: number;
  type?: 'mac' | 'ip' | 'ip-subnet';
  mac?: string;
  ip?: string;
  ip_subnet?: string;
  interface?: string;
  vlan?: string;
  description?: string;
}

export interface SwitchControllerVlan {
  name: string;
  q_origin_key: string;
  vlan_id?: number;
  description?: string;
  dhcp_snooping?: 'enable' | 'disable';
  arp_inspection?: 'enable' | 'disable';
  learning?: 'enable' | 'disable';
  mcast_snooping_flood_reports?: 'enable' | 'disable';
  mcast_snooping_flood_traffic?: 'enable' | 'disable';
  igmp_snooping?: 'enable' | 'disable';
  igmps_flood_reports?: 'enable' | 'disable';
  igmps_flood_traffic?: 'enable' | 'disable';
  mrouter_ports?: string[];
  dhcp_server_access_list?: 'enable' | 'disable';
  member?: SwitchControllerVlanMember[];
}

export interface SwitchControllerVlanMember {
  member_name: string;
  q_origin_key: string;
  vlan_id?: number;
  description?: string;
}

export interface SwitchControllerStpSettings {
  status?: 'enable' | 'disable';
  priority?: '0' | '4096' | '8192' | '12288' | '16384' | '20480' | '24576' | '28672' | '32768' | '36864' | '40960' | '45056' | '49152' | '53248' | '57344' | '61440';
  hello_time?: number;
  forward_delay?: number;
  max_age?: number;
  max_hops?: number;
  pending_timer?: number;
}

export interface SwitchControllerIgmpSnooping {
  aging_time?: number;
  flood_unknown_multicast?: 'enable' | 'disable';
}

// Wireless Controller
export interface WirelessControllerVap {
  name: string;
  q_origin_key: string;
  ssid?: string;
  broadcast_ssid?: 'enable' | 'disable';
  security?: 'open' | 'captive-portal' | 'wep64' | 'wep128' | 'wpa-personal' | 'wpa-enterprise' | 'wpa-only-personal' | 'wpa-only-enterprise' | 'wpa2-only-personal' | 'wpa2-only-enterprise' | 'wpa3-enterprise' | 'wpa3-personal' | 'wpa3-sae' | 'osene';
  fast_roaming?: 'enable' | 'disable';
  external_fast_roaming?: 'enable' | 'disable';
  pmf?: 'disable' | 'enable' | 'optional';
  pmf_assoc_comeback_timeout?: number;
  pmf_sa_query_retry_timeout?: number;
  okc?: 'enable' | 'disable';
  passphrase?: string;
  radius_server?: string;
  local_authentication?: 'enable' | 'disable';
  local_bridging?: 'enable' | 'disable';
  vlanid?: number;
  dynamic_vlan?: 'enable' | 'disable';
  multicast_rate?: 'auto' | '1' | '2' | '5.5' | '6' | '9' | '11' | '12' | '18' | '24' | '36' | '48' | '54';
  band?: '802.11a' | '802.11b' | '802.11g' | '802.11n' | '802.11n-5G' | '802.11ac' | '802.11ax-5G' | '802.11ax' | '802.11n,g-only' | '802.11g-only' | '802.11n-only' | '802.11n-5G-only' | '802.11ac-only' | '802.11ac,n-only' | '802.11n-5G-only' | '802.11ax-5G-only' | '802.11ax,ac-only' | '802.11ax,n-only' | '802.11ax-only' | '802.11ax,g-only';
  schedule?: string;
  schedule_block?: string[];
  utm_log?: 'enable' | 'disable';
  address?: string;
  address_group?: string;
  address_group_policy?: 'disable' | 'allow' | 'deny';
  target_wake_time?: 'enable' | 'disable';
  tunnel_echo_interval?: number;
  tunnel_fallback_interval?: number;
  user_idle_timeout?: number;
  radio_2g_threshold?: string;
  radio_5g_threshold?: string;
  radio_sensitivity?: 'enable' | 'disable';
  quarantine?: 'enable' | 'disable';
  radio_resource_provisioning?: 'enable' | 'disable';
  auto_power_level?: 'enable' | 'disable';
  auto_power_high?: number;
  auto_power_low?: number;
  vap_all?: 'tunnel' | 'bridge' | 'manual' | 'disabled';
  vdom?: string;
  ssid_disable?: 'enable' | 'disable';
  intra_vap_privacy?: 'enable' | 'disable';
  schedule_duration?: number;
  schedule_duration_type?: 'minutes' | 'hours';
  schedule_date?: string;
  atf_weight?: number;
  split_tunneling?: 'enable' | 'disable';
  auth_cert?: string;
  auth_portal_addr?: string;
  auth_portal_port?: number;
  intra_vap_privacy_disable?: 'enable' | 'disable';
  station_locate?: 'enable' | 'disable';
  dhcp_lease_time?: number;
  dhcp_option43_insertion?: 'enable' | 'disable';
  dhcp_option82_insertion?: 'enable' | 'disable';
  dhcp_option82_circuit_id_insertion?: 'style-1' | 'style-2' | 'disable';
  dhcp_option82_remote_id_insertion?: 'style-1' | 'style-2' | 'disable';
  ptksa_replay_counter?: 'enable' | 'disable';
  gas_comeback_delay?: number;
  gas_fragmentation_limit?: number;
  wpa_passphrase?: string;
  wpa_pmk?: string;
  wpa_gtk_rekey?: 'enable' | 'disable';
  wpa_gtk_rekey_intv?: number;
  eapol_key_retries?: 'disable' | 'enable';
  tkip_counter_measure?: 'enable' | 'disable';
  mac_filter?: 'enable' | 'disable';
  mac_filter_policy_other?: 'allow' | 'deny';
  mac_filter_list?: WirelessControllerMacFilterList[];
  dynamic_mapping?: WirelessControllerVapDynamicMapping[];
}

export interface WirelessControllerMacFilterList {
  id: number;
  q_origin_key: number;
  mac?: string;
  mac_filter_policy?: 'allow' | 'deny';
  description?: string;
}

export interface WirelessControllerVapDynamicMapping {
  _scope?: WirelessControllerVapDynamicMappingScope[];
  wtp_group?: string;
}

export interface WirelessControllerVapDynamicMappingScope {
  name: string;
  q_origin_key: string;
  vdom?: string;
}

// Exportar todos los tipos
export * from './index';

/**
 * FortiGate MCP V7.6 - Model Context Protocol
 * 
 * Un protocolo de contexto de modelo completo para FortiGate V7.6 que proporciona:
 * - Control completo de todos los módulos de seguridad
 * - Validación de comandos con token
 * - Análisis detallado de cambios
 * - Función de rollback
 * 
 * @version 1.0.0
 * @author FortiGate MCP Team
 */

// Tipos
export * from './types';

// Utilidades
export { FortiGateClient } from './utils/FortiGateClient';
export { ChangeAnalyzer, ChangeAnalysis, ChangeDetail, ChangeImpact } from './utils/ChangeAnalyzer';
export { RollbackManager, RollbackResult, RollbackPlan, RollbackStep } from './utils/RollbackManager';
export { logger, auditLogger, rollbackLogger, validationLogger } from './utils/logger';

// Validadores
export { TokenValidator } from './validators/TokenValidator';
export { CommandValidator, CommandValidationContext } from './validators/CommandValidator';

// Módulos Base
export { BaseModule, ModuleConfig } from './modules/BaseModule';

// Módulos de Seguridad
export { AntivirusModule } from './modules/AntivirusModule';
export { IpsModule } from './modules/IpsModule';
export { WebFilterModule } from './modules/WebFilterModule';
export { CasbModule } from './modules/CasbModule';
export { SslInspectionModule } from './modules/SslInspectionModule';

// Importaciones para la clase principal
import { FortiGateConfig, SystemInfo } from './types';
import { FortiGateClient } from './utils/FortiGateClient';
import { ChangeAnalyzer } from './utils/ChangeAnalyzer';
import { RollbackManager } from './utils/RollbackManager';
import { CommandValidator } from './validators/CommandValidator';
import { TokenValidator } from './validators/TokenValidator';
import { logger } from './utils/logger';

// Módulos
import { AntivirusModule } from './modules/AntivirusModule';
import { IpsModule } from './modules/IpsModule';
import { WebFilterModule } from './modules/WebFilterModule';
import { CasbModule } from './modules/CasbModule';
import { SslInspectionModule } from './modules/SslInspectionModule';

/**
 * Clase principal de FortiGate MCP
 * Integra todos los módulos y funcionalidades
 */
export class FortiGateMCP {
  private client: FortiGateClient;
  private changeAnalyzer: ChangeAnalyzer;
  private rollbackManager: RollbackManager;
  private commandValidator: CommandValidator;
  private tokenValidator: TokenValidator;

  // Módulos de seguridad
  public antivirus: AntivirusModule;
  public ips: IpsModule;
  public webfilter: WebFilterModule;
  public casb: CasbModule;
  public sslInspection: SslInspectionModule;

  constructor(config: FortiGateConfig) {
    // Inicializar utilidades principales
    this.client = new FortiGateClient(config);
    this.changeAnalyzer = new ChangeAnalyzer();
    this.rollbackManager = new RollbackManager(this.client, this.changeAnalyzer);
    this.commandValidator = new CommandValidator();
    this.tokenValidator = new TokenValidator();

    // Inicializar módulos de seguridad
    this.antivirus = new AntivirusModule(this.client, this.changeAnalyzer);
    this.ips = new IpsModule(this.client, this.changeAnalyzer);
    this.webfilter = new WebFilterModule(this.client, this.changeAnalyzer);
    this.casb = new CasbModule(this.client, this.changeAnalyzer);
    this.sslInspection = new SslInspectionModule(this.client, this.changeAnalyzer);

    logger.info('FortiGate MCP V7.6 inicializado', {
      host: config.host,
      vdom: config.vdom || 'root'
    });
  }

  /**
   * Verifica la conectividad con el FortiGate
   */
  async checkConnectivity(): Promise<boolean> {
    return this.client.checkConnectivity();
  }

  /**
   * Obtiene información del sistema
   */
  async getSystemInfo(): Promise<SystemInfo> {
    const response = await this.client.getSystemStatus();
    return {
      hostname: response.hostname,
      serial: response.serial,
      version: response.version,
      build: response.build,
      model: response.model,
      model_name: response.model_name,
      model_number: response.model_number,
      model_serial: response.model_serial,
      uptime: response.uptime,
      current_time: response.current_time,
      last_reboot_reason: response.last_reboot_reason,
      fortiguard_version: response.fortiguard_version
    };
  }

  /**
   * Obtiene la versión de FortiOS
   */
  async getVersion(): Promise<string> {
    return this.client.getVersion();
  }

  /**
   * Obtiene el cliente HTTP subyacente
   */
  getClient(): FortiGateClient {
    return this.client;
  }

  /**
   * Obtiene el analizador de cambios
   */
  getChangeAnalyzer(): ChangeAnalyzer {
    return this.changeAnalyzer;
  }

  /**
   * Obtiene el gestor de rollback
   */
  getRollbackManager(): RollbackManager {
    return this.rollbackManager;
  }

  /**
   * Obtiene el validador de comandos
   */
  getCommandValidator(): CommandValidator {
    return this.commandValidator;
  }

  /**
   * Obtiene el validador de tokens
   */
  getTokenValidator(): TokenValidator {
    return this.tokenValidator;
  }

  /**
   * Cambia el VDOM actual
   */
  setVdom(vdom: string): void {
    this.client.setVdom(vdom);
    logger.info(`VDOM cambiado a: ${vdom}`);
  }

  /**
   * Obtiene el VDOM actual
   */
  getCurrentVdom(): string {
    return this.client.getCurrentVdom();
  }

  /**
   * Actualiza el token de autenticación
   */
  updateToken(newToken: string): void {
    this.client.updateToken(newToken);
  }

  /**
   * Obtiene estadísticas de uso de la API
   */
  getApiStats(): { requestCount: number; lastRequestTime: number } {
    return this.client.getApiStats();
  }

  /**
   * Genera un informe completo del sistema
   */
  async generateSystemReport(): Promise<string> {
    const info = await this.getSystemInfo();
    const changes = this.changeAnalyzer.getStatistics();
    
    let report = '=== INFORME DEL SISTEMA FORTIGATE ===\n\n';
    report += `Generado: ${new Date().toISOString()}\n\n`;
    
    report += '=== INFORMACIÓN DEL SISTEMA ===\n';
    report += `Hostname: ${info.hostname}\n`;
    report += `Serial: ${info.serial}\n`;
    report += `Versión: ${info.version}\n`;
    report += `Build: ${info.build}\n`;
    report += `Modelo: ${info.model}\n`;
    report += `Uptime: ${info.uptime}\n`;
    report += `FortiGuard: ${info.fortiguard_version}\n\n`;

    report += '=== ESTADÍSTICAS DE CAMBIOS ===\n';
    report += `Total de cambios: ${changes.totalChanges}\n`;
    report += `Rollback disponibles: ${changes.rollbackableChanges}\n`;
    
    report += '\nPor módulo:\n';
    for (const [module, count] of Object.entries(changes.changesByModule)) {
      report += `  - ${module}: ${count}\n`;
    }

    return report;
  }

  /**
   * Realiza un backup de la configuración
   */
  async backupConfiguration(): Promise<string> {
    const path = '/api/v2/monitor/system/config/backup';
    const response = await this.client.get(path);
    return JSON.stringify(response, null, 2);
  }

  /**
   * Obtiene el estado de salud del sistema
   */
  async getHealthStatus(): Promise<any> {
    const path = '/api/v2/monitor/system/health-check';
    return this.client.get(path);
  }

  /**
   * Obtiene estadísticas de recursos
   */
  async getResourceStats(): Promise<any> {
    const path = '/api/v2/monitor/system/resource';
    return this.client.get(path);
  }

  /**
   * Obtiene información de interfaces
   */
  async getInterfaceStatus(): Promise<any> {
    const path = '/api/v2/monitor/system/interface';
    return this.client.get(path);
  }

  /**
   * Obtiene estadísticas de sesiones
   */
  async getSessionStats(): Promise<any> {
    const path = '/api/v2/monitor/firewall/session';
    return this.client.get(path);
  }

  /**
   * Obtiene estadísticas de políticas de firewall
   */
  async getPolicyStats(): Promise<any> {
    const path = '/api/v2/monitor/firewall/policy';
    return this.client.get(path);
  }

  /**
   * Limpia el historial de cambios
   */
  clearChangeHistory(): void {
    this.changeAnalyzer.clearAllChanges();
  }

  /**
   * Limpia el historial de rollbacks
   */
  clearRollbackHistory(): void {
    this.rollbackManager.clearHistory();
  }

  /**
   * Destruye la instancia y libera recursos
   */
  destroy(): void {
    logger.info('FortiGate MCP V7.6 destruido');
  }
}

export default FortiGateMCP;

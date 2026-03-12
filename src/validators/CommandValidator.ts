/**
 * Validador de comandos para FortiGate MCP
 * Valida que los comandos y configuraciones sean correctos antes de ejecutarlos
 */

import { ValidationResult, ValidationError, ValidationWarning } from '../types';
import { logger, validationLogger } from '../utils/logger';

export interface CommandValidationContext {
  vdom?: string;
  user?: string;
  module?: string;
  operation?: 'create' | 'update' | 'delete' | 'read';
  previousState?: any;
  newState?: any;
}

export class CommandValidator {
  private readonly forbiddenCommands: string[] = [
    'execute factoryreset',
    'execute erase-disk',
    'execute format',
    'config system admin',
    'delete system admin',
    'execute reboot',
    'execute shutdown',
    'execute auto-install',
    'execute restore',
    'execute certificate ca',
    'execute certificate crl',
    'execute certificate local',
    'execute certificate remote'
  ];

  private readonly dangerousCommands: string[] = [
    'execute backup',
    'execute restore',
    'execute certificate',
    'config system global',
    'config system ha',
    'config system interface',
    'delete system interface',
    'config router static',
    'delete router static'
  ];

  private readonly readonlyPaths: string[] = [
    '/api/v2/monitor/',
    '/api/v2/cmdb/system/status',
    '/api/v2/cmdb/system/time'
  ];

  /**
   * Valida un comando antes de ejecutarlo
   */
  validateCommand(command: string, context?: CommandValidationContext): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    validationLogger.info('Validando comando', { command, context });

    // Verificar comandos prohibidos
    for (const forbidden of this.forbiddenCommands) {
      if (command.toLowerCase().includes(forbidden.toLowerCase())) {
        errors.push({
          field: 'command',
          message: `Comando prohibido detectado: ${forbidden}`,
          code: 'FORBIDDEN_COMMAND'
        });
      }
    }

    // Advertir sobre comandos peligrosos
    for (const dangerous of this.dangerousCommands) {
      if (command.toLowerCase().includes(dangerous.toLowerCase())) {
        warnings.push({
          field: 'command',
          message: `Comando potencialmente peligroso: ${dangerous}. Verifique antes de ejecutar.`,
          suggestion: 'Considere crear un punto de rollback antes de ejecutar este comando'
        });
      }
    }

    // Validar longitud del comando
    if (command.length > 4000) {
      errors.push({
        field: 'command',
        message: 'El comando excede la longitud máxima permitida (4000 caracteres)',
        code: 'COMMAND_TOO_LONG'
      });
    }

    // Validar caracteres permitidos
    const invalidChars = /[<>\"';&|`$]/;
    if (invalidChars.test(command)) {
      errors.push({
        field: 'command',
        message: 'El comando contiene caracteres no permitidos',
        code: 'INVALID_CHARACTERS'
      });
    }

    // Validar contexto
    if (context) {
      const contextValidation = this.validateContext(context);
      errors.push(...contextValidation.errors);
      warnings.push(...contextValidation.warnings);
    }

    const result = { valid: errors.length === 0, errors, warnings };
    
    validationLogger.info('Resultado de validación', { 
      command, 
      valid: result.valid, 
      errorCount: errors.length, 
      warningCount: warnings.length 
    });

    return result;
  }

  /**
   * Valida una operación de API
   */
  validateApiOperation(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
    path: string,
    data?: any,
    context?: CommandValidationContext
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    validationLogger.info('Validando operación API', { method, path, context });

    // Validar método HTTP
    const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    if (!validMethods.includes(method)) {
      errors.push({
        field: 'method',
        message: `Método HTTP no válido: ${method}`,
        code: 'INVALID_HTTP_METHOD'
      });
    }

    // Validar path
    if (!path.startsWith('/api/')) {
      errors.push({
        field: 'path',
        message: 'El path debe comenzar con /api/',
        code: 'INVALID_API_PATH'
      });
    }

    // Verificar operaciones de lectura en paths de solo lectura
    if (method === 'GET' && this.readonlyPaths.some(readonly => path.includes(readonly))) {
      // Esto es válido, no hacer nada
    }

    // Validar operaciones de escritura
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      // Verificar que no sea un path de solo lectura
      if (this.readonlyPaths.some(readonly => path.includes(readonly))) {
        errors.push({
          field: 'path',
          message: 'No se pueden realizar operaciones de escritura en este recurso',
          code: 'READONLY_RESOURCE'
        });
      }

      // Validar datos para operaciones de escritura
      if (data) {
        const dataValidation = this.validateData(data, method);
        errors.push(...dataValidation.errors);
        warnings.push(...dataValidation.warnings);
      }
    }

    // Validar eliminación de recursos críticos
    if (method === 'DELETE') {
      const criticalPaths = [
        'firewall/policy',
        'system/interface',
        'system/admin',
        'router/static'
      ];
      
      for (const critical of criticalPaths) {
        if (path.includes(critical)) {
          warnings.push({
            field: 'path',
            message: `Está eliminando un recurso crítico: ${critical}`,
            suggestion: 'Asegúrese de tener un backup antes de continuar'
          });
        }
      }
    }

    // Validar contexto
    if (context) {
      const contextValidation = this.validateContext(context);
      errors.push(...contextValidation.errors);
      warnings.push(...contextValidation.warnings);
    }

    const result = { valid: errors.length === 0, errors, warnings };
    
    validationLogger.info('Resultado de validación API', { 
      method, 
      path, 
      valid: result.valid, 
      errorCount: errors.length, 
      warningCount: warnings.length 
    });

    return result;
  }

  /**
   * Valida los datos de una operación
   */
  private validateData(data: any, method: string): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (typeof data !== 'object' || data === null) {
      errors.push({
        field: 'data',
        message: 'Los datos deben ser un objeto válido',
        code: 'INVALID_DATA_FORMAT'
      });
      return { valid: false, errors, warnings };
    }

    // Validar campos requeridos comunes
    if (method === 'POST' && !data.name && !data.policyid) {
      warnings.push({
        field: 'data',
        message: 'No se encontró campo de identificación (name o policyid)',
        suggestion: 'Asegúrese de incluir un identificador único'
      });
    }

    // Validar valores de campos específicos
    for (const [key, value] of Object.entries(data)) {
      // Validar strings
      if (typeof value === 'string') {
        if (value.length > 255) {
          errors.push({
            field: key,
            message: `El campo ${key} excede la longitud máxima de 255 caracteres`,
            code: 'FIELD_TOO_LONG'
          });
        }

        // Validar caracteres especiales en nombres
        if ((key === 'name' || key === 'q_origin_key') && /[<>\"';&|`$]/.test(value)) {
          errors.push({
            field: key,
            message: `El campo ${key} contiene caracteres no permitidos`,
            code: 'INVALID_FIELD_CHARACTERS'
          });
        }
      }

      // Validar números
      if (typeof value === 'number') {
        if (value < 0 && !['priority', 'priority_adjust'].includes(key)) {
          warnings.push({
            field: key,
            message: `El campo ${key} tiene un valor negativo`,
            suggestion: 'Verifique que esto sea intencional'
          });
        }
      }

      // Validar arrays
      if (Array.isArray(value)) {
        if (value.length > 1000) {
          errors.push({
            field: key,
            message: `El array ${key} excede el tamaño máximo permitido (1000 elementos)`,
            code: 'ARRAY_TOO_LARGE'
          });
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida el contexto de una operación
   */
  private validateContext(context: CommandValidationContext): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar VDOM
    if (context.vdom) {
      if (context.vdom.length > 32) {
        errors.push({
          field: 'vdom',
          message: 'El nombre del VDOM no puede exceder 32 caracteres',
          code: 'VDOM_NAME_TOO_LONG'
        });
      }

      if (!/^[a-zA-Z0-9_-]+$/.test(context.vdom)) {
        errors.push({
          field: 'vdom',
          message: 'El nombre del VDOM contiene caracteres no válidos',
          code: 'VDOM_INVALID_NAME'
        });
      }
    }

    // Validar usuario
    if (context.user) {
      if (context.user.length > 64) {
        errors.push({
          field: 'user',
          message: 'El nombre de usuario no puede exceder 64 caracteres',
          code: 'USERNAME_TOO_LONG'
        });
      }
    }

    // Validar operación
    if (context.operation) {
      const validOperations = ['create', 'update', 'delete', 'read'];
      if (!validOperations.includes(context.operation)) {
        errors.push({
          field: 'operation',
          message: `Operación no válida: ${context.operation}`,
          code: 'INVALID_OPERATION'
        });
      }
    }

    // Validar módulo
    if (context.module) {
      const validModules = [
        'firewall',
        'system',
        'router',
        'vpn',
        'user',
        'log',
        'antivirus',
        'webfilter',
        'dnsfilter',
        'ips',
        'application',
        'ssl',
        'voip',
        'dlp',
        'waf',
        'casb',
        'ztna',
        'wireless',
        'switch-controller'
      ];

      if (!validModules.includes(context.module.toLowerCase())) {
        warnings.push({
          field: 'module',
          message: `Módulo no reconocido: ${context.module}`,
          suggestion: 'Verifique que el módulo esté correctamente escrito'
        });
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida una configuración de perfil de seguridad
   */
  validateSecurityProfile(profile: any, profileType: string): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar nombre
    if (!profile.name) {
      errors.push({
        field: 'name',
        message: 'El nombre del perfil es requerido',
        code: 'PROFILE_NAME_REQUIRED'
      });
    }

    // Validaciones específicas por tipo de perfil
    switch (profileType.toLowerCase()) {
      case 'antivirus':
        if (profile.inspection_mode && !['proxy', 'flow'].includes(profile.inspection_mode)) {
          errors.push({
            field: 'inspection_mode',
            message: 'Modo de inspección no válido para antivirus',
            code: 'INVALID_INSPECTION_MODE'
          });
        }
        break;

      case 'webfilter':
        if (profile.ftgd_wf && profile.ftgd_wf.filters) {
          for (const filter of profile.ftgd_wf.filters) {
            if (!filter.category === undefined) {
              errors.push({
                field: 'category',
                message: 'La categoría es requerida en los filtros',
                code: 'FILTER_CATEGORY_REQUIRED'
              });
            }
          }
        }
        break;

      case 'ips':
        if (profile.entries) {
          for (const entry of profile.entries) {
            if (entry.action && !['pass', 'block', 'reset', 'default'].includes(entry.action)) {
              errors.push({
                field: 'action',
                message: 'Acción no válida en entrada IPS',
                code: 'INVALID_IPS_ACTION'
              });
            }
          }
        }
        break;
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida una política de firewall
   */
  validateFirewallPolicy(policy: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar interfaces
    if (!policy.srcintf || policy.srcintf.length === 0) {
      errors.push({
        field: 'srcintf',
        message: 'Se requiere al menos una interfaz de origen',
        code: 'SRC_INTF_REQUIRED'
      });
    }

    if (!policy.dstintf || policy.dstintf.length === 0) {
      errors.push({
        field: 'dstintf',
        message: 'Se requiere al menos una interfaz de destino',
        code: 'DST_INTF_REQUIRED'
      });
    }

    // Validar direcciones
    if (!policy.srcaddr || policy.srcaddr.length === 0) {
      errors.push({
        field: 'srcaddr',
        message: 'Se requiere al menos una dirección de origen',
        code: 'SRC_ADDR_REQUIRED'
      });
    }

    if (!policy.dstaddr || policy.dstaddr.length === 0) {
      errors.push({
        field: 'dstaddr',
        message: 'Se requiere al menos una dirección de destino',
        code: 'DST_ADDR_REQUIRED'
      });
    }

    // Validar acción
    if (policy.action && !['accept', 'deny', 'ipsec'].includes(policy.action)) {
      errors.push({
        field: 'action',
        message: 'Acción no válida en política de firewall',
        code: 'INVALID_POLICY_ACTION'
      });
    }

    // Advertir sobre políticas sin perfil de seguridad
    if (policy.action === 'accept' && 
        !policy.utm_status || policy.utm_status === 'disable') {
      warnings.push({
        field: 'utm_status',
        message: 'La política no tiene UTM habilitado',
        suggestion: 'Considere habilitar perfiles de seguridad para mayor protección'
      });
    }

    // Validar NAT
    if (policy.nat === 'enable' && policy.ippool === 'enable' && 
        (!policy.poolname || policy.poolname.length === 0)) {
      errors.push({
        field: 'poolname',
        message: 'Se requiere un IP Pool cuando NAT e IP Pool están habilitados',
        code: 'IPPOOL_REQUIRED'
      });
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida una configuración de interfaz
   */
  validateInterface(iface: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar nombre
    if (!iface.name) {
      errors.push({
        field: 'name',
        message: 'El nombre de la interfaz es requerido',
        code: 'INTERFACE_NAME_REQUIRED'
      });
    }

    // Validar tipo
    if (iface.type && ![
      'physical', 'vlan', 'aggregate', 'redundant', 'tunnel', 
      'vdom-link', 'loopback', 'switch', 'hard-switch', 'hdlc', 'ppp', 'ssl'
    ].includes(iface.type)) {
      errors.push({
        field: 'type',
        message: 'Tipo de interfaz no válido',
        code: 'INVALID_INTERFACE_TYPE'
      });
    }

    // Validar modo
    if (iface.mode && !['static', 'dhcp', 'pppoe'].includes(iface.mode)) {
      errors.push({
        field: 'mode',
        message: 'Modo de interfaz no válido',
        code: 'INVALID_INTERFACE_MODE'
      });
    }

    // Validar IP en modo estático
    if (iface.mode === 'static' && !iface.ip) {
      errors.push({
        field: 'ip',
        message: 'Se requiere dirección IP en modo estático',
        code: 'IP_REQUIRED_FOR_STATIC'
      });
    }

    // Validar VLAN ID
    if (iface.type === 'vlan') {
      if (iface.vlanid === undefined) {
        errors.push({
          field: 'vlanid',
          message: 'Se requiere VLAN ID para interfaces VLAN',
          code: 'VLAN_ID_REQUIRED'
        });
      }
      if (iface.vlanid < 1 || iface.vlanid > 4094) {
        errors.push({
          field: 'vlanid',
          message: 'VLAN ID debe estar entre 1 y 4094',
          code: 'INVALID_VLAN_ID'
        });
      }
    }

    // Advertir sobre interfaces sin acceso de administración
    if (iface.allowaccess === undefined || iface.allowaccess === '') {
      warnings.push({
        field: 'allowaccess',
        message: 'La interfaz no tiene métodos de acceso de administración configurados',
        suggestion: 'Considere habilitar HTTPS o SSH para administración remota'
      });
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida una configuración de VPN IPsec
   */
  validateIpsecConfig(config: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar nombre
    if (!config.name) {
      errors.push({
        field: 'name',
        message: 'El nombre de la configuración IPsec es requerido',
        code: 'IPSEC_NAME_REQUIRED'
      });
    }

    // Validar interfaz
    if (!config.interface) {
      errors.push({
        field: 'interface',
        message: 'La interfaz es requerida para IPsec',
        code: 'IPSEC_INTERFACE_REQUIRED'
      });
    }

    // Validar tipo de peer
    if (config.peertype && !['any', 'one', 'dialup', 'peer', 'peergrp'].includes(config.peertype)) {
      errors.push({
        field: 'peertype',
        message: 'Tipo de peer no válido',
        code: 'INVALID_PEERTYPE'
      });
    }

    // Validar método de autenticación
    if (config.auth_method && !['psk', 'signature', 'signature-auth-enforcement'].includes(config.auth_method)) {
      errors.push({
        field: 'auth_method',
        message: 'Método de autenticación no válido',
        code: 'INVALID_AUTH_METHOD'
      });
    }

    // Validar PSK
    if (config.auth_method === 'psk' && !config.passwd && config.ike_version !== '2') {
      warnings.push({
        field: 'passwd',
        message: 'No se ha configurado PSK',
        suggestion: 'Asegúrese de configurar el PSK en ambos extremos del túnel'
      });
    }

    // Validar grupos DH
    if (config.dhgrp) {
      const validDhGroups = ['1', '2', '5', '14', '15', '16', '17', '18', '19', '20', '21', '27', '28', '29', '30', '31', '32'];
      for (const group of config.dhgrp) {
        if (!validDhGroups.includes(group)) {
          errors.push({
            field: 'dhgrp',
            message: `Grupo DH no válido: ${group}`,
            code: 'INVALID_DH_GROUP'
          });
        }
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Valida una configuración de usuario
   */
  validateUserConfig(user: any): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    // Validar nombre
    if (!user.name) {
      errors.push({
        field: 'name',
        message: 'El nombre de usuario es requerido',
        code: 'USERNAME_REQUIRED'
      });
    }

    // Validar tipo
    if (user.type && ![
      'password', 'radius', 'tacacs+', 'ldap', 'fortitoken', 
      'email', 'sms', 'two-factor', 'certificate', 'fsso', 'fortitoken-cloud'
    ].includes(user.type)) {
      errors.push({
        field: 'type',
        message: 'Tipo de usuario no válido',
        code: 'INVALID_USER_TYPE'
      });
    }

    // Validar contraseña para usuarios locales
    if (user.type === 'password' && !user.passwd) {
      warnings.push({
        field: 'passwd',
        message: 'No se ha configurado contraseña para el usuario local',
        suggestion: 'Configure una contraseña segura'
      });
    }

    // Validar servidor RADIUS/TACACS+/LDAP
    if (['radius', 'tacacs+', 'ldap'].includes(user.type)) {
      const serverField = user.type === 'radius' ? 'radius_server' : 
                         user.type === 'tacacs+' ? 'tacacs+-server' : 'ldap_server';
      if (!user[serverField]) {
        errors.push({
          field: serverField,
          message: `Se requiere servidor ${user.type} configurado`,
          code: 'AUTH_SERVER_REQUIRED'
        });
      }
    }

    return { valid: errors.length === 0, errors, warnings };
  }

  /**
   * Agrega un comando a la lista de prohibidos
   */
  addForbiddenCommand(command: string): void {
    this.forbiddenCommands.push(command.toLowerCase());
    logger.info(`Comando agregado a lista de prohibidos: ${command}`);
  }

  /**
   * Agrega un comando a la lista de peligrosos
   */
  addDangerousCommand(command: string): void {
    this.dangerousCommands.push(command.toLowerCase());
    logger.info(`Comando agregado a lista de peligrosos: ${command}`);
  }

  /**
   * Obtiene la lista de comandos prohibidos
   */
  getForbiddenCommands(): string[] {
    return [...this.forbiddenCommands];
  }

  /**
   * Obtiene la lista de comandos peligrosos
   */
  getDangerousCommands(): string[] {
    return [...this.dangerousCommands];
  }
}

export default CommandValidator;

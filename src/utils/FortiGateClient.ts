/**
 * Cliente HTTP para la API de FortiGate V7.6
 * Maneja autenticación por token, solicitudes HTTP y gestión de errores
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { FortiGateConfig, FortiGateApiResponse, FortiGateApiError } from '../types';
import { logger } from './logger';
import { TokenValidator } from '../validators/TokenValidator';

export class FortiGateClient {
  private client: AxiosInstance;
  private config: FortiGateConfig;
  private tokenValidator: TokenValidator;
  private requestCount: number = 0;
  private lastRequestTime: number = 0;
  private readonly RATE_LIMIT_REQUESTS = 100;
  private readonly RATE_LIMIT_WINDOW = 60000; // 1 minuto

  constructor(config: FortiGateConfig) {
    this.config = {
      port: 443,
      https: true,
      verifySsl: true,
      timeout: 30000,
      vdom: 'root',
      ...config
    };

    this.tokenValidator = new TokenValidator();
    this.validateConfig();
    this.client = this.createAxiosInstance();
    this.setupInterceptors();
  }

  /**
   * Valida la configuración del cliente
   */
  private validateConfig(): void {
    if (!this.config.host) {
      throw new Error('El host de FortiGate es requerido');
    }

    if (!this.config.token) {
      throw new Error('El token de API es requerido');
    }

    // Validar el formato del token
    const tokenValidation = this.tokenValidator.validate(this.config.token);
    if (!tokenValidation.valid) {
      throw new Error(`Token inválido: ${tokenValidation.errors.map(e => e.message).join(', ')}`);
    }

    // Validar formato de host
    const hostRegex = /^[a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9](?::\d+)?$/;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?::\d+)?$/;
    
    if (!hostRegex.test(this.config.host) && !ipRegex.test(this.config.host)) {
      throw new Error('Formato de host inválido');
    }
  }

  /**
   * Crea la instancia de Axios configurada
   */
  private createAxiosInstance(): AxiosInstance {
    const protocol = this.config.https ? 'https' : 'http';
    const baseURL = `${protocol}://${this.config.host}:${this.config.port}`;

    return axios.create({
      baseURL,
      timeout: this.config.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': `Bearer ${this.config.token}`
      },
      httpsAgent: this.config.https && !this.config.verifySsl ? 
        new (require('https').Agent)({ rejectUnauthorized: false }) : 
        undefined
    });
  }

  /**
   * Configura interceptores de request/response
   */
  private setupInterceptors(): void {
    // Interceptor de request
    this.client.interceptors.request.use(
      (config) => {
        this.checkRateLimit();
        this.requestCount++;
        this.lastRequestTime = Date.now();

        logger.debug(`[${config.method?.toUpperCase()}] ${config.url}`, {
          headers: config.headers,
          params: config.params,
          data: config.data
        });

        // Agregar VDOM si está configurado
        if (this.config.vdom && config.params) {
          config.params.vdom = this.config.vdom;
        } else if (this.config.vdom) {
          config.params = { vdom: this.config.vdom };
        }

        return config;
      },
      (error) => {
        logger.error('Error en request:', error);
        return Promise.reject(error);
      }
    );

    // Interceptor de response
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        logger.debug(`[${response.status}] ${response.config.url}`, {
          data: response.data
        });
        return response;
      },
      (error: AxiosError<FortiGateApiError>) => {
        this.handleApiError(error);
        return Promise.reject(error);
      }
    );
  }

  /**
   * Verifica y controla el rate limiting
   */
  private checkRateLimit(): void {
    const now = Date.now();
    if (now - this.lastRequestTime > this.RATE_LIMIT_WINDOW) {
      this.requestCount = 0;
    }

    if (this.requestCount >= this.RATE_LIMIT_REQUESTS) {
      throw new Error('Rate limit excedido. Espere antes de realizar más solicitudes.');
    }
  }

  /**
   * Maneja errores de la API de FortiGate
   */
  private handleApiError(error: AxiosError<FortiGateApiError>): void {
    if (error.response) {
      const { status, data } = error.response;
      const errorMessage = data?.error_message || data?.details || error.message;

      logger.error(`Error API FortiGate [${status}]:`, {
        url: error.config?.url,
        method: error.config?.method,
        error: data,
        message: errorMessage
      });

      switch (status) {
        case 401:
          throw new Error(`Autenticación fallida: ${errorMessage}. Verifique el token de API.`);
        case 403:
          throw new Error(`Acceso denegado: ${errorMessage}. Verifique los permisos del administrador.`);
        case 404:
          throw new Error(`Recurso no encontrado: ${errorMessage}`);
        case 405:
          throw new Error(`Método no permitido: ${errorMessage}`);
        case 413:
          throw new Error(`Payload demasiado grande: ${errorMessage}`);
        case 422:
          throw new Error(`Datos inválidos: ${errorMessage}`);
        case 429:
          throw new Error(`Rate limit excedido: ${errorMessage}. Espere antes de reintentar.`);
        case 500:
          throw new Error(`Error interno del servidor: ${errorMessage}`);
        case 503:
          throw new Error(`Servicio no disponible: ${errorMessage}. El FortiGate puede estar sobrecargado.`);
        default:
          throw new Error(`Error ${status}: ${errorMessage}`);
      }
    } else if (error.request) {
      logger.error('Error de conexión:', {
        url: error.config?.url,
        message: error.message
      });
      throw new Error(`Error de conexión: No se pudo conectar a ${this.config.host}. Verifique la conectividad de red.`);
    } else {
      logger.error('Error de configuración:', error.message);
      throw new Error(`Error de configuración: ${error.message}`);
    }
  }

  /**
   * Realiza una solicitud GET
   */
  async get<T>(url: string, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const response = await this.client.get<FortiGateApiResponse<T>>(url, { params });
    return response.data;
  }

  /**
   * Realiza una solicitud POST
   */
  async post<T>(url: string, data?: any, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const response = await this.client.post<FortiGateApiResponse<T>>(url, data, { params });
    return response.data;
  }

  /**
   * Realiza una solicitud PUT
   */
  async put<T>(url: string, data?: any, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const response = await this.client.put<FortiGateApiResponse<T>>(url, data, { params });
    return response.data;
  }

  /**
   * Realiza una solicitud DELETE
   */
  async delete<T>(url: string, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const response = await this.client.delete<FortiGateApiResponse<T>>(url, { params });
    return response.data;
  }

  /**
   * Realiza una solicitud PATCH
   */
  async patch<T>(url: string, data?: any, params?: Record<string, any>): Promise<FortiGateApiResponse<T>> {
    const response = await this.client.patch<FortiGateApiResponse<T>>(url, data, { params });
    return response.data;
  }

  /**
   * Obtiene información del sistema
   */
  async getSystemStatus(): Promise<any> {
    return this.get('/api/v2/monitor/system/status');
  }

  /**
   * Obtiene la versión de FortiOS
   */
  async getVersion(): Promise<string> {
    const response = await this.getSystemStatus();
    return response.version;
  }

  /**
   * Verifica la conectividad con el FortiGate
   */
  async checkConnectivity(): Promise<boolean> {
    try {
      await this.getSystemStatus();
      return true;
    } catch (error) {
      return false;
    }
  }

  /**
   * Obtiene el VDOM actual
   */
  getCurrentVdom(): string {
    return this.config.vdom || 'root';
  }

  /**
   * Cambia el VDOM para las siguientes solicitudes
   */
  setVdom(vdom: string): void {
    this.config.vdom = vdom;
  }

  /**
   * Obtiene la configuración actual
   */
  getConfig(): FortiGateConfig {
    return { ...this.config };
  }

  /**
   * Actualiza el token de autenticación
   */
  updateToken(newToken: string): void {
    const validation = this.tokenValidator.validate(newToken);
    if (!validation.valid) {
      throw new Error(`Token inválido: ${validation.errors.map(e => e.message).join(', ')}`);
    }

    this.config.token = newToken;
    this.client.defaults.headers['Authorization'] = `Bearer ${newToken}`;
    logger.info('Token actualizado exitosamente');
  }

  /**
   * Obtiene estadísticas de uso de la API
   */
  getApiStats(): { requestCount: number; lastRequestTime: number } {
    return {
      requestCount: this.requestCount,
      lastRequestTime: this.lastRequestTime
    };
  }

  /**
   * Reinicia el contador de solicitudes
   */
  resetApiStats(): void {
    this.requestCount = 0;
    this.lastRequestTime = 0;
  }

  /**
   * Ejecuta múltiples solicitudes en paralelo
   */
  async parallelRequests<T>(requests: Array<() => Promise<T>>): Promise<T[]> {
    return Promise.all(requests.map(req => req()));
  }

  /**
   * Ejecuta múltiples solicitudes en serie
   */
  async serialRequests<T>(requests: Array<() => Promise<T>>): Promise<T[]> {
    const results: T[] = [];
    for (const request of requests) {
      results.push(await request());
    }
    return results;
  }

  /**
   * Realiza una solicitud con reintentos
   */
  async requestWithRetry<T>(
    requestFn: () => Promise<T>,
    maxRetries: number = 3,
    delay: number = 1000
  ): Promise<T> {
    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        return await requestFn();
      } catch (error) {
        lastError = error as Error;
        
        // No reintentar en errores de autenticación o validación
        if (error instanceof Error && 
            (error.message.includes('Autenticación fallida') || 
             error.message.includes('Acceso denegado') ||
             error.message.includes('Datos inválidos'))) {
          throw error;
        }

        if (attempt < maxRetries) {
          logger.warn(`Intento ${attempt} fallido, reintentando en ${delay}ms...`);
          await this.sleep(delay);
          delay *= 2; // Backoff exponencial
        }
      }
    }

    throw lastError || new Error('Todos los intentos fallaron');
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Obtiene el URL base de la API
   */
  getBaseUrl(): string {
    const protocol = this.config.https ? 'https' : 'http';
    return `${protocol}://${this.config.host}:${this.config.port}`;
  }

  /**
   * Construye un URL completo para un endpoint
   */
  buildUrl(endpoint: string): string {
    const baseUrl = this.getBaseUrl();
    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    return `${baseUrl}${cleanEndpoint}`;
  }
}

export default FortiGateClient;

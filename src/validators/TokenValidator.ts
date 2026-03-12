/**
 * Validador de tokens de API de FortiGate
 */

import { ValidationResult, ValidationError } from '../types';
import CryptoJS from 'crypto-js';

export class TokenValidator {
  private readonly MIN_TOKEN_LENGTH = 32;
  private readonly MAX_TOKEN_LENGTH = 128;
  private readonly TOKEN_PATTERN = /^[a-zA-Z0-9_-]+$/;

  /**
   * Valida un token de API de FortiGate
   */
  validate(token: string): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    // Verificar que el token no esté vacío
    if (!token || token.trim().length === 0) {
      errors.push({
        field: 'token',
        message: 'El token no puede estar vacío',
        code: 'TOKEN_EMPTY'
      });
      return { valid: false, errors, warnings };
    }

    // Verificar longitud mínima
    if (token.length < this.MIN_TOKEN_LENGTH) {
      errors.push({
        field: 'token',
        message: `El token debe tener al menos ${this.MIN_TOKEN_LENGTH} caracteres`,
        code: 'TOKEN_TOO_SHORT'
      });
    }

    // Verificar longitud máxima
    if (token.length > this.MAX_TOKEN_LENGTH) {
      errors.push({
        field: 'token',
        message: `El token no puede tener más de ${this.MAX_TOKEN_LENGTH} caracteres`,
        code: 'TOKEN_TOO_LONG'
      });
    }

    // Verificar caracteres permitidos
    if (!this.TOKEN_PATTERN.test(token)) {
      errors.push({
        field: 'token',
        message: 'El token contiene caracteres no válidos. Solo se permiten letras, números, guiones y guiones bajos',
        code: 'TOKEN_INVALID_CHARS'
      });
    }

    // Verificar entropía del token (debe tener suficiente aleatoriedad)
    const entropy = this.calculateEntropy(token);
    if (entropy < 3.5) {
      warnings.push({
        field: 'token',
        message: 'El token tiene baja entropía, podría ser predecible',
        code: 'TOKEN_LOW_ENTROPY'
      });
    }

    // Verificar que no sea un token de ejemplo o de prueba
    const lowerToken = token.toLowerCase();
    const forbiddenPatterns = ['test', 'example', 'demo', 'sample', '123456', 'password', 'admin'];
    for (const pattern of forbiddenPatterns) {
      if (lowerToken.includes(pattern)) {
        warnings.push({
          field: 'token',
          message: `El token contiene la palabra prohibida: ${pattern}`,
          code: 'TOKEN_FORBIDDEN_PATTERN'
        });
      }
    }

    // Verificar que no tenga secuencias repetitivas
    if (this.hasRepeatingSequences(token)) {
      warnings.push({
        field: 'token',
        message: 'El token contiene secuencias repetitivas',
        code: 'TOKEN_REPEATING_SEQUENCES'
      });
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Calcula la entropía de Shannon del token
   */
  private calculateEntropy(token: string): number {
    const freq: Record<string, number> = {};
    for (const char of token) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = token.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Verifica si el token tiene secuencias repetitivas
   */
  private hasRepeatingSequences(token: string): boolean {
    for (let len = 2; len <= token.length / 2; len++) {
      for (let i = 0; i <= token.length - len * 2; i++) {
        const sequence = token.substring(i, i + len);
        const rest = token.substring(i + len);
        if (rest.includes(sequence)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Genera un hash del token para almacenamiento seguro
   */
  hashToken(token: string): string {
    return CryptoJS.SHA256(token).toString();
  }

  /**
   * Máscara el token para logging seguro
   */
  maskToken(token: string): string {
    if (token.length <= 8) {
      return '****';
    }
    return token.substring(0, 4) + '****' + token.substring(token.length - 4);
  }

  /**
   * Verifica si un token está expirado (basado en timestamp si está disponible)
   */
  isTokenExpired(token: string, expirationDate?: Date): boolean {
    if (expirationDate) {
      return new Date() > expirationDate;
    }
    // Los tokens de FortiGate no tienen fecha de expiración incorporada
    // Esta función es para tokens con metadatos adicionales
    return false;
  }

  /**
   * Genera un token de prueba válido (solo para testing)
   */
  generateTestToken(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-/';
    let token = '';
    for (let i = 0; i < 64; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }

  /**
   * Valida el formato de un header de autorización
   */
  validateAuthHeader(authHeader: string): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationError[] = [];

    if (!authHeader) {
      errors.push({
        field: 'Authorization',
        message: 'El header de autorización es requerido',
        code: 'AUTH_HEADER_MISSING'
      });
      return { valid: false, errors, warnings };
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2) {
      errors.push({
        field: 'Authorization',
        message: 'Formato inválido. Debe ser: Bearer <token>',
        code: 'AUTH_HEADER_INVALID_FORMAT'
      });
      return { valid: false, errors, warnings };
    }

    const [scheme, token] = parts;

    if (scheme !== 'Bearer') {
      errors.push({
        field: 'Authorization',
        message: `Esquema de autenticación no soportado: ${scheme}. Use 'Bearer'`,
        code: 'AUTH_HEADER_INVALID_SCHEME'
      });
    }

    const tokenValidation = this.validate(token);
    errors.push(...tokenValidation.errors);
    warnings.push(...tokenValidation.warnings);

    return {
      valid: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Extrae el token de un header de autorización
   */
  extractToken(authHeader: string): string | null {
    const parts = authHeader.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      return parts[1];
    }
    return null;
  }

  /**
   * Valida múltiples tokens
   */
  validateMultiple(tokens: string[]): Record<string, ValidationResult> {
    const results: Record<string, ValidationResult> = {};
    for (const token of tokens) {
      results[this.maskToken(token)] = this.validate(token);
    }
    return results;
  }

  /**
   * Obtiene estadísticas de un token
   */
  getTokenStats(token: string): {
    length: number;
    entropy: number;
    uniqueChars: number;
    hasUpperCase: boolean;
    hasLowerCase: boolean;
    hasNumbers: boolean;
    hasSpecialChars: boolean;
  } {
    return {
      length: token.length,
      entropy: this.calculateEntropy(token),
      uniqueChars: new Set(token).size,
      hasUpperCase: /[A-Z]/.test(token),
      hasLowerCase: /[a-z]/.test(token),
      hasNumbers: /[0-9]/.test(token),
      hasSpecialChars: /[_-]/.test(token)
    };
  }
}

export default TokenValidator;

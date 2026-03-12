/**
 * Tests para TokenValidator
 */

import { TokenValidator } from '../src/validators/TokenValidator';

describe('TokenValidator', () => {
  let validator: TokenValidator;

  beforeEach(() => {
    validator = new TokenValidator();
  });

  describe('validate', () => {
    it('should validate a correct token', () => {
      const validToken = 'a'.repeat(64);
      const result = validator.validate(validToken);
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject empty token', () => {
      const result = validator.validate('');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'TOKEN_EMPTY' })
      );
    });

    it('should reject token that is too short', () => {
      const shortToken = 'short';
      const result = validator.validate(shortToken);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'TOKEN_TOO_SHORT' })
      );
    });

    it('should reject token with invalid characters', () => {
      const invalidToken = 'a'.repeat(32) + '!@#$%';
      const result = validator.validate(invalidToken);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'TOKEN_INVALID_CHARS' })
      );
    });

    it('should warn about low entropy tokens', () => {
      const lowEntropyToken = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
      const result = validator.validate(lowEntropyToken);
      
      expect(result.warnings).toContainEqual(
        expect.objectContaining({ code: 'TOKEN_LOW_ENTROPY' })
      );
    });

    it('should warn about forbidden patterns', () => {
      const tokenWithPattern = 'test' + 'a'.repeat(40);
      const result = validator.validate(tokenWithPattern);
      
      expect(result.warnings).toContainEqual(
        expect.objectContaining({ code: 'TOKEN_FORBIDDEN_PATTERN' })
      );
    });
  });

  describe('hashToken', () => {
    it('should return a valid SHA256 hash', () => {
      const token = 'test-token';
      const hash = validator.hashToken(token);
      
      expect(hash).toHaveLength(64); // SHA256 produces 64 hex characters
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('should return consistent hash for same token', () => {
      const token = 'test-token';
      const hash1 = validator.hashToken(token);
      const hash2 = validator.hashToken(token);
      
      expect(hash1).toBe(hash2);
    });

    it('should return different hashes for different tokens', () => {
      const hash1 = validator.hashToken('token1');
      const hash2 = validator.hashToken('token2');
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('maskToken', () => {
    it('should mask a long token correctly', () => {
      const token = 'abcdefghijklmnop';
      const masked = validator.maskToken(token);
      
      expect(masked).toBe('abcd****mnop');
    });

    it('should return **** for short tokens', () => {
      const token = 'short';
      const masked = validator.maskToken(token);
      
      expect(masked).toBe('****');
    });
  });

  describe('validateAuthHeader', () => {
    it('should validate correct Bearer token header', () => {
      const validToken = 'a'.repeat(64);
      const header = `Bearer ${validToken}`;
      const result = validator.validateAuthHeader(header);
      
      expect(result.valid).toBe(true);
    });

    it('should reject missing header', () => {
      const result = validator.validateAuthHeader('');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'AUTH_HEADER_MISSING' })
      );
    });

    it('should reject invalid format', () => {
      const result = validator.validateAuthHeader('invalid-format');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'AUTH_HEADER_INVALID_FORMAT' })
      );
    });

    it('should reject non-Bearer scheme', () => {
      const result = validator.validateAuthHeader('Basic dXNlcjpwYXNz');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'AUTH_HEADER_INVALID_SCHEME' })
      );
    });
  });

  describe('extractToken', () => {
    it('should extract token from Bearer header', () => {
      const token = 'my-token';
      const header = `Bearer ${token}`;
      const extracted = validator.extractToken(header);
      
      expect(extracted).toBe(token);
    });

    it('should return null for invalid format', () => {
      const extracted = validator.extractToken('invalid');
      
      expect(extracted).toBeNull();
    });

    it('should return null for non-Bearer scheme', () => {
      const extracted = validator.extractToken('Basic dXNlcjpwYXNz');
      
      expect(extracted).toBeNull();
    });
  });

  describe('getTokenStats', () => {
    it('should return correct stats for a token', () => {
      const token = 'AbCdEfGh123456';
      const stats = validator.getTokenStats(token);
      
      expect(stats.length).toBe(token.length);
      expect(stats.hasUpperCase).toBe(true);
      expect(stats.hasLowerCase).toBe(true);
      expect(stats.hasNumbers).toBe(true);
      expect(stats.uniqueChars).toBeLessThanOrEqual(token.length);
    });
  });
});

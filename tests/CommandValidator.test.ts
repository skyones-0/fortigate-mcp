/**
 * Tests para CommandValidator
 */

import { CommandValidator } from '../src/validators/CommandValidator';

describe('CommandValidator', () => {
  let validator: CommandValidator;

  beforeEach(() => {
    validator = new CommandValidator();
  });

  describe('validateCommand', () => {
    it('should validate a safe command', () => {
      const result = validator.validateCommand('show firewall policy');
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should reject forbidden commands', () => {
      const result = validator.validateCommand('execute factoryreset');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'FORBIDDEN_COMMAND' })
      );
    });

    it('should warn about dangerous commands', () => {
      const result = validator.validateCommand('execute backup');
      
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.warnings).toContainEqual(
        expect.objectContaining({ code: expect.stringContaining('DANGEROUS') })
      );
    });

    it('should reject commands that are too long', () => {
      const longCommand = 'a'.repeat(4001);
      const result = validator.validateCommand(longCommand);
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'COMMAND_TOO_LONG' })
      );
    });

    it('should reject commands with invalid characters', () => {
      const result = validator.validateCommand('config firewall policy; rm -rf /');
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INVALID_CHARACTERS' })
      );
    });
  });

  describe('validateApiOperation', () => {
    it('should validate a valid GET operation', () => {
      const result = validator.validateApiOperation(
        'GET',
        '/api/v2/cmdb/firewall/address'
      );
      
      expect(result.valid).toBe(true);
    });

    it('should validate a valid POST operation', () => {
      const result = validator.validateApiOperation(
        'POST',
        '/api/v2/cmdb/firewall/address',
        { name: 'Test', subnet: '192.168.1.0 255.255.255.0' }
      );
      
      expect(result.valid).toBe(true);
    });

    it('should reject invalid HTTP method', () => {
      const result = validator.validateApiOperation(
        'INVALID' as any,
        '/api/v2/cmdb/firewall/address'
      );
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INVALID_HTTP_METHOD' })
      );
    });

    it('should reject invalid API path', () => {
      const result = validator.validateApiOperation(
        'GET',
        '/invalid/path'
      );
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INVALID_API_PATH' })
      );
    });

    it('should warn about deleting critical resources', () => {
      const result = validator.validateApiOperation(
        'DELETE',
        '/api/v2/cmdb/firewall/policy/1'
      );
      
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('validateSecurityProfile', () => {
    it('should validate a valid antivirus profile', () => {
      const result = validator.validateSecurityProfile(
        {
          name: 'Test-AV',
          inspection_mode: 'flow'
        },
        'antivirus'
      );
      
      expect(result.valid).toBe(true);
    });

    it('should reject profile without name', () => {
      const result = validator.validateSecurityProfile(
        { inspection_mode: 'flow' },
        'antivirus'
      );
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'PROFILE_NAME_REQUIRED' })
      );
    });

    it('should reject invalid inspection mode', () => {
      const result = validator.validateSecurityProfile(
        {
          name: 'Test',
          inspection_mode: 'invalid'
        },
        'antivirus'
      );
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INVALID_INSPECTION_MODE' })
      );
    });
  });

  describe('validateFirewallPolicy', () => {
    it('should validate a valid firewall policy', () => {
      const result = validator.validateFirewallPolicy({
        name: 'Test-Policy',
        srcintf: [{ name: 'port1' }],
        dstintf: [{ name: 'port2' }],
        srcaddr: [{ name: 'all' }],
        dstaddr: [{ name: 'all' }],
        action: 'accept',
        service: [{ name: 'HTTP' }]
      });
      
      expect(result.valid).toBe(true);
    });

    it('should reject policy without source interface', () => {
      const result = validator.validateFirewallPolicy({
        name: 'Test',
        dstintf: [{ name: 'port2' }],
        srcaddr: [{ name: 'all' }],
        dstaddr: [{ name: 'all' }],
        action: 'accept'
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'SRC_INTF_REQUIRED' })
      );
    });

    it('should reject policy without destination interface', () => {
      const result = validator.validateFirewallPolicy({
        name: 'Test',
        srcintf: [{ name: 'port1' }],
        srcaddr: [{ name: 'all' }],
        dstaddr: [{ name: 'all' }],
        action: 'accept'
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'DST_INTF_REQUIRED' })
      );
    });

    it('should warn about policy without UTM', () => {
      const result = validator.validateFirewallPolicy({
        name: 'Test',
        srcintf: [{ name: 'port1' }],
        dstintf: [{ name: 'port2' }],
        srcaddr: [{ name: 'all' }],
        dstaddr: [{ name: 'all' }],
        action: 'accept',
        utm_status: 'disable'
      });
      
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });

  describe('validateInterface', () => {
    it('should validate a valid interface', () => {
      const result = validator.validateInterface({
        name: 'port1',
        type: 'physical',
        mode: 'static',
        ip: '192.168.1.1 255.255.255.0'
      });
      
      expect(result.valid).toBe(true);
    });

    it('should reject interface without name', () => {
      const result = validator.validateInterface({
        type: 'physical',
        mode: 'static'
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INTERFACE_NAME_REQUIRED' })
      );
    });

    it('should reject VLAN without VLAN ID', () => {
      const result = validator.validateInterface({
        name: 'vlan100',
        type: 'vlan',
        mode: 'static'
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'VLAN_ID_REQUIRED' })
      );
    });

    it('should reject invalid VLAN ID', () => {
      const result = validator.validateInterface({
        name: 'vlan9999',
        type: 'vlan',
        vlanid: 9999,
        mode: 'static'
      });
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'INVALID_VLAN_ID' })
      );
    });
  });

  describe('addForbiddenCommand', () => {
    it('should add a command to forbidden list', () => {
      validator.addForbiddenCommand('test-forbidden-command');
      
      const result = validator.validateCommand('test-forbidden-command');
      expect(result.valid).toBe(false);
      expect(result.errors).toContainEqual(
        expect.objectContaining({ code: 'FORBIDDEN_COMMAND' })
      );
    });
  });

  describe('addDangerousCommand', () => {
    it('should add a command to dangerous list', () => {
      validator.addDangerousCommand('test-dangerous-command');
      
      const result = validator.validateCommand('test-dangerous-command');
      expect(result.warnings.length).toBeGreaterThan(0);
    });
  });
});

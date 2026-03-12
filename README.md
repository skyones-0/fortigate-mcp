# FortiGate MCP V7.6

## Model Context Protocol for FortiGate V7.6

A complete Model Context Protocol for FortiGate V7.6 that provides full control of all security modules, command validation with token authentication, detailed change analysis, and rollback functionality.

## Features

- **Secure authentication** with FortiGate API tokens
- **Command validation** before execution
- **Detailed change analysis** with impact assessment
- **Rollback functionality** to revert changes
- **Complete coverage** of FortiGate V7.6 security modules
- **TypeScript** with full type definitions
- **Comprehensive logging** for audit and operations

## Supported Modules

### UTM/NGFW Security Modules

| Module | Description | Version |
|--------|-------------|---------|
| **Antivirus** | Antivirus profiles, real-time scanning, quarantine | V7.6 |
| **IPS** | Intrusion Prevention System, signatures, anomaly detection | V7.6 |
| **Web Filter** | Web content filtering, FortiGuard categories | V7.6 |
| **DNS Filter** | DNS filtering, malicious domain blocking | V7.6 |
| **Application Control** | Application control, application signatures | V7.6 |
| **CASB** | Cloud Access Security Broker for SaaS | V7.6 |
| **DLP** | Data Loss Prevention | V7.6 |
| **File Filter** | File filtering by type | V7.6 |
| **Email Filter** | Spam and email content filtering | V7.6 |
| **Video Filter** | Video content filtering (YouTube, Vimeo, etc.) | V7.6 |
| **VoIP** | Security for VoIP/SIP traffic | V7.6 |

### Deep Inspection Modules (DPI)

| Module | Description | Version |
|--------|-------------|---------|
| **SSL/SSH Inspection** | Deep Packet Inspection for SSL/TLS and SSH | V7.6 |
| **WAF** | Web Application Firewall | V7.6 |
| **Virtual Patch** | Virtual patches for vulnerabilities | V7.6 |
| **ICAP** | ICAP server integration | V7.6 |

### Network and VPN Modules

| Module | Description | Version |
|--------|-------------|---------|
| **Firewall Policy** | IPv4/IPv6 firewall policies | V7.6 |
| **NAT** | NAT, Virtual IPs, IP Pools | V7.6 |
| **IPsec VPN** | IPsec VPN tunnels, phase 1 and 2 | V7.6 |
| **SSL VPN** | SSL VPN with tunnel and web mode | V7.6 |
| **ZTNA** | Zero Trust Network Access | V7.6 |
| **SD-WAN** | SD-WAN, zones, services, SLA | V7.6 |
| **Routing** | Static and dynamic routes (OSPF, BGP) | V7.6 |

### System Modules

| Module | Description | Version |
|--------|-------------|---------|
| **Interfaces** | Physical and VLAN interface configuration | V7.6 |
| **HA** | High Availability, clustering | V7.6 |
| **VDOM** | Virtual Domains | V7.6 |
| **Administrators** | Admin users, access profiles | V7.6 |
| **Logging** | Log configuration, FortiAnalyzer, syslog | V7.6 |
| **SNMP** | SNMP configuration | V7.6 |
| **Certificates** | Certificate management | V7.6 |
| **DHCP** | DHCP servers | V7.6 |

### Device Management Modules

| Module | Description | Version |
|--------|-------------|---------|
| **Switch Controller** | FortiSwitch management | V7.6 |
| **Wireless Controller** | FortiAP and WLAN management | V7.6 |
| **FortiExtender** | FortiExtender management | V7.6 |

## Installation

```bash
npm install fortigate-mcp-v7.6
```

## Quick Start

```typescript
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

// Connection configuration
const config = {
  host: '192.168.1.99',
  port: 443,
  token: 'your-api-token-here',
  https: true,
  verifySsl: false,
  vdom: 'root'
};

// Initialize MCP
const mcp = new FortiGateMCP(config);

// Check connectivity
const connected = await mcp.checkConnectivity();
console.log(`Connected: ${connected}`);

// Get system information
const info = await mcp.getSystemInfo();
console.log(`FortiOS ${info.version} - ${info.hostname}`);
```

## Configuration

### Creating an API Token in FortiGate

1. Navigate to **System > Administrators**
2. Create a new **REST API** administrator
3. Assign an **Admin Profile** with required permissions
4. Save and copy the generated token

### Permission Configuration

| Functionality | Required Permissions |
|---------------|---------------------|
| Read configuration | `read` on corresponding modules |
| Modify configuration | `read-write` on corresponding modules |
| Monitoring | `read` on Log & Report |
| System administration | `read-write` on System |

## Security Modules

### Antivirus

```typescript
// Create an antivirus profile
const profile = await mcp.antivirus.createProfile({
  name: 'AV-Corporate-Profile',
  inspection_mode: 'flow',
  ftgd_analytics: 'suspicious',
  http: {
    av_scan: 'enable',
    av_block: 'enable',
    av_quarantine: 'enable'
  },
  ftp: {
    av_scan: 'enable',
    av_block: 'enable'
  }
});

// Get existing profiles
const profiles = await mcp.antivirus.getProfiles();

// Update a profile
await mcp.antivirus.updateProfile('AV-Corporate-Profile', {
  ftgd_analytics: 'everything'
});

// Delete a profile
await mcp.antivirus.deleteProfile('AV-Corporate-Profile');

// Get detection logs
const logs = await mcp.antivirus.getDetectionLogs({
  since: '2024-01-01',
  limit: 100
});

// Update database
await mcp.antivirus.updateDatabase();
```

### IPS (Intrusion Prevention System)

```typescript
// Create an IPS sensor
const sensor = await mcp.ips.createSensor({
  name: 'IPS-Corporate',
  comment: 'IPS sensor for corporate network',
  entries: [
    {
      id: 1,
      severity: ['critical', 'high'],
      action: 'block',
      status: 'enable',
      log: 'enable'
    },
    {
      id: 2,
      severity: ['medium'],
      action: 'monitor',
      status: 'enable',
      log: 'enable'
    }
  ]
});

// Add an entry to the sensor
await mcp.ips.addEntry('IPS-Corporate', {
  id: 3,
  protocol: ['TCP'],
  action: 'block',
  status: 'enable'
});

// Configure botnet scanning
await mcp.ips.setBotnetScanning('IPS-Corporate', 'block');

// Get detected intrusions
const intrusions = await mcp.ips.getDetectedIntrusions({
  since: '2024-01-01',
  limit: 100
});
```

### Web Filter

```typescript
// Create a web filter profile
const profile = await mcp.webfilter.createProfile({
  name: 'WF-Corporate',
  inspection_mode: 'flow',
  ftgd_wf: {
    filters: [
      {
        id: 1,
        category: 26, // Adult Material
        action: 'block',
        log: 'enable'
      },
      {
        id: 2,
        category: 61, // Malicious Websites
        action: 'block',
        log: 'enable'
      }
    ]
  }
});

// Add a category filter
await mcp.webfilter.addFortiguardFilter('WF-Corporate', {
  id: 3,
  category: 88, // Spam
  action: 'block',
  log: 'enable'
});

// Configure logging
await mcp.webfilter.setUrlLogging('WF-Corporate', 'enable', 'enable');

// Get blocked URLs
const blocked = await mcp.webfilter.getBlockedUrls({
  limit: 100
});
```

### CASB (Cloud Access Security Broker)

```typescript
// Create a CASB profile for Microsoft 365
const profile = await mcp.casb.createMicrosoft365Profile('CASB-M365', {
  blockUpload: false,
  blockDownload: true,
  blockShare: true,
  allowedTenants: ['mycompany.com', 'mycompany.onmicrosoft.com']
});

// Create a CASB profile for Google Workspace
const googleProfile = await mcp.casb.createGoogleWorkspaceProfile('CASB-Google', {
  blockUpload: true,
  allowedDomains: ['mycompany.com']
});

// Add a SaaS application
await mcp.casb.addSaasApplication('CASB-M365', {
  name: 'dropbox',
  status: 'enable',
  default_action: 'block',
  log: 'enable'
});

// Get CASB events
const events = await mcp.casb.getEvents({
  since: '2024-01-01',
  limit: 100
});

// Get policy violations
const violations = await mcp.casb.getPolicyViolations();
```

### SSL/SSH Inspection (DPI)

```typescript
// Create a deep inspection profile
const profile = await mcp.sslInspection.createDeepInspectionProfile(
  'DPI-Deep',
  'My-CA-Certificate'
);

// Create a certificate inspection profile
const certProfile = await mcp.sslInspection.createCertificateInspectionProfile(
  'DPI-Certificate'
);

// Configure HTTPS inspection
await mcp.sslInspection.setHttpsInspectionMode('DPI-Deep', 'deep-inspection');

// Add address exemption
await mcp.sslInspection.addAddressExemption('DPI-Deep', [
  '10.0.0.0/8',
  '192.168.1.0/24'
]);

// Add wildcard FQDN exemption
await mcp.sslInspection.addWildcardFqdnExemption('DPI-Deep', [
  '*.bank.com',
  '*.health.gov'
]);

// Configure SSL/TLS versions
await mcp.sslInspection.setSslVersions(
  'DPI-Deep',
  'https',
  'tls-1.2',
  'tls-1.3'
);

// Get detected SSL anomalies
const anomalies = await mcp.sslInspection.getSslAnomalies();
```

## Command Validation

```typescript
// Validate a command before execution
const validation = mcp.getCommandValidator().validateCommand(
  'config firewall policy',
  {
    module: 'firewall',
    operation: 'update',
    vdom: 'root'
  }
);

if (!validation.valid) {
  console.error('Errors:', validation.errors);
  console.warn('Warnings:', validation.warnings);
}

// Validate an API operation
const apiValidation = mcp.getCommandValidator().validateApiOperation(
  'POST',
  '/api/v2/cmdb/firewall/policy',
  { name: 'New-Policy', action: 'accept' },
  { module: 'firewall', operation: 'create' }
);

// Validate a security profile
const profileValidation = mcp.getCommandValidator().validateSecurityProfile(
  { name: 'Test', inspection_mode: 'flow' },
  'antivirus'
);

// Validate a firewall policy
const policyValidation = mcp.getCommandValidator().validateFirewallPolicy({
  name: 'Policy-Test',
  srcintf: [{ name: 'port1' }],
  dstintf: [{ name: 'port2' }],
  srcaddr: [{ name: 'all' }],
  dstaddr: [{ name: 'all' }],
  action: 'accept',
  service: [{ name: 'HTTP' }]
});
```

## Change Analysis

```typescript
// Changes are automatically logged when using modules

// Get all changes
const allChanges = mcp.getChangeAnalyzer().getAllChanges();

// Get changes by module
const firewallChanges = mcp.getChangeAnalyzer().getChangesByModule('firewall');

// Get changes by operation
const creations = mcp.getChangeAnalyzer().getChangesByOperation('create');

// Analyze a specific change
const analysis = mcp.getChangeAnalyzer().analyzeChange(changeId);
console.log(`Impact: ${analysis?.impact.level}`);
console.log(`Description: ${analysis?.impact.description}`);
console.log(`Affected resources: ${analysis?.impact.affectedResources}`);

// Generate a diff between states
const diff = mcp.getChangeAnalyzer().generateDiff(oldState, newState);

// Generate a change report
const report = mcp.getChangeAnalyzer().generateReport(
  new Date('2024-01-01'),
  new Date()
);

// Export changes to JSON
const jsonExport = mcp.getChangeAnalyzer().exportToJson();

// Get statistics
const stats = mcp.getChangeAnalyzer().getStatistics();
console.log(`Total changes: ${stats.totalChanges}`);
console.log(`By module:`, stats.changesByModule);
```

## Rollback Functionality

```typescript
// Create a rollback plan
const plan = await mcp.getRollbackManager().createRollbackPlan(changeId);
console.log(`Steps: ${plan?.steps.length}`);
console.log(`Estimated time: ${plan?.estimatedTime}s`);
console.log(`Risk: ${plan?.risk}`);

// Preview a rollback
const preview = await mcp.getRollbackManager().previewRollback(changeId);
console.log(`Analysis:`, preview.analysis);

// Check if a change can be rolled back
const canRollback = mcp.getRollbackManager().canRollback(changeId);

// Execute a rollback (dry run)
const dryRunResult = await mcp.getRollbackManager().executeRollback(changeId, {
  dryRun: true
});

// Execute an actual rollback
const result = await mcp.getRollbackManager().executeRollback(changeId, {
  dryRun: false,
  skipVerification: false,
  timeout: 300000 // 5 minutes
});

if (result.success) {
  console.log('Rollback successful:', result.message);
  console.log('Details:', result.details);
} else {
  console.error('Rollback failed:', result.error);
}

// Execute rollback for multiple changes
const batchResults = await mcp.getRollbackManager().executeBatchRollback(
  [changeId1, changeId2, changeId3],
  { stopOnError: true }
);

// Get rollback history
const history = mcp.getRollbackManager().getRollbackHistory();

// Generate rollback report
const rollbackReport = mcp.getRollbackManager().generateReport();
```

## Token Management

```typescript
// Validate a token
const tokenValidation = mcp.getTokenValidator().validate(token);
if (!tokenValidation.valid) {
  console.error('Invalid token:', tokenValidation.errors);
}

// Get token statistics
const tokenStats = mcp.getTokenValidator().getTokenStats(token);
console.log(`Entropy: ${tokenStats.entropy}`);
console.log(`Unique characters: ${tokenStats.uniqueChars}`);

// Mask token for secure logging
const masked = mcp.getTokenValidator().maskToken(token);
console.log(`Token: ${masked}`); // shows: abcd****wxyz

// Update the token
mcp.updateToken('new-token-here');
```

## Monitoring and Logs

```typescript
// Get system statistics
const health = await mcp.getHealthStatus();
const resources = await mcp.getResourceStats();

// Get interface status
const interfaces = await mcp.getInterfaceStatus();

// Get session statistics
const sessions = await mcp.getSessionStats();

// Get policy statistics
const policies = await mcp.getPolicyStats();

// Generate system report
const systemReport = await mcp.generateSystemReport();

// Get API statistics
const apiStats = mcp.getApiStats();
console.log(`Requests: ${apiStats.requestCount}`);
```

## Advanced Configuration

### Change VDOM

```typescript
// Change to a specific VDOM
mcp.setVdom('customer-a');

// All subsequent operations will use this VDOM
const policies = await mcp.firewall.getPolicies();

// Return to root VDOM
mcp.setVdom('root');
```

### Error Handling

```typescript
import { FortiGateMCP } from 'fortigate-mcp-v7.6';

try {
  const mcp = new FortiGateMCP(config);
  
  // Check connectivity first
  const connected = await mcp.checkConnectivity();
  if (!connected) {
    throw new Error('Could not connect to FortiGate');
  }
  
  // Operations...
  
} catch (error) {
  if (error.message.includes('401')) {
    console.error('Authentication error - check token');
  } else if (error.message.includes('403')) {
    console.error('Access denied - check permissions');
  } else if (error.message.includes('404')) {
    console.error('Resource not found');
  } else {
    console.error('Error:', error.message);
  }
}
```

### Logging

Logs are stored in the `logs/` directory:

- `combined.log` - General logs
- `error.log` - Errors
- `audit.log` - Change audit
- `rollback.log` - Rollback operations
- `validation.log` - Validations

```typescript
import { logger, auditLogger } from 'fortigate-mcp-v7.6';

// Add custom logs
logger.info('Operation completed', { details: '...' });
auditLogger.info('Important change made', { change: '...' });
```

## API Reference

### FortiGateMCP

| Method | Description |
|--------|-------------|
| `checkConnectivity()` | Check connection to FortiGate |
| `getSystemInfo()` | Get system information |
| `getVersion()` | Get FortiOS version |
| `setVdom(vdom)` | Change current VDOM |
| `getCurrentVdom()` | Get current VDOM |
| `updateToken(token)` | Update authentication token |
| `generateSystemReport()` | Generate complete report |
| `getHealthStatus()` | Get health status |
| `getResourceStats()` | Get resource statistics |

### Modules

Each module provides standard CRUD methods:

| Method | Description |
|--------|-------------|
| `getAll(params?)` | Get all resources |
| `getById(id)` | Get a specific resource |
| `create(data)` | Create a new resource |
| `update(id, data)` | Update a resource |
| `delete(id)` | Delete a resource |
| `clone(id, newName)` | Clone a resource |
| `exists(id)` | Check if a resource exists |

## Requirements

- Node.js >= 18.0.0
- FortiGate with FortiOS V7.6
- FortiGate API Token

## Dependencies

- axios: ^1.6.0
- zod: ^3.22.4
- winston: ^3.11.0
- crypto-js: ^4.2.0
- uuid: ^9.0.1
- date-fns: ^2.30.0

## License

MIT

## Support

To report issues or request features, please use the project issue tracker.

## Changelog

### v1.0.0
- Initial release
- Full support for FortiOS V7.6
- All security modules implemented
- Command validation system
- Change analysis with impact assessment
- Complete rollback functionality

---

**Note**: This MCP is designed for FortiGate administrators with networking and security knowledge. Always test in a lab environment before deploying changes to production.


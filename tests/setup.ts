/**
 * Configuración de tests para FortiGate MCP
 */

// Configurar variables de entorno para tests
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';

// Mock para axios
jest.mock('axios', () => ({
  create: jest.fn(() => ({
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    delete: jest.fn(),
    patch: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() }
    }
  })),
  get: jest.fn(),
  post: jest.fn(),
  put: jest.fn(),
  delete: jest.fn(),
  patch: jest.fn()
}));

// Configuración global
global.console = {
  ...console,
  // Silenciar logs durante tests
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: console.error
};

// Cleanup después de cada test
afterEach(() => {
  jest.clearAllMocks();
});

/* eslint-disable @typescript-eslint/no-explicit-any */
import { SAMLProvider, AuthUtils, DefaultLogger } from '../src';

describe('AuthUtils', () => {
  describe('generateNonce', () => {
    it('should generate a nonce of default length', () => {
      const nonce = AuthUtils.generateNonce();
      expect(nonce).toHaveLength(64); // 32 bytes * 2 (hex)
      expect(nonce).toMatch(/^[a-f0-9]+$/);
    });

    it('should generate a nonce of specified length', () => {
      const nonce = AuthUtils.generateNonce(16);
      expect(nonce).toHaveLength(32); // 16 bytes * 2 (hex)
      expect(nonce).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('base64UrlEncode/Decode', () => {
    it('should encode and decode strings correctly', () => {
      const original = 'Hello, World! 123 🌍';
      const encoded = AuthUtils.base64UrlEncode(original);
      const decoded = AuthUtils.base64UrlDecode(encoded);

      expect(decoded).toBe(original);
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });
  });

  describe('generateCSRFToken', () => {
    it('should generate a valid CSRF token', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(token).toHaveLength(64); // 32 bytes * 2 (hex)
      expect(token).toMatch(/^[a-f0-9]+$/);
    });
  });

  describe('validateCSRFToken', () => {
    it('should validate matching tokens', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken(token, token)).toBe(true);
    });

    it('should reject non-matching tokens', () => {
      const token1 = AuthUtils.generateCSRFToken();
      const token2 = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken(token1, token2)).toBe(false);
    });

    it('should reject empty tokens', () => {
      const token = AuthUtils.generateCSRFToken();
      expect(AuthUtils.validateCSRFToken('', token)).toBe(false);
      expect(AuthUtils.validateCSRFToken(token, '')).toBe(false);
    });
  });

  describe('sanitizeReturnTo', () => {
    it('should allow valid paths', () => {
      expect(AuthUtils.sanitizeReturnTo('/dashboard')).toBe('/dashboard');
      expect(AuthUtils.sanitizeReturnTo('/this/path/is/ok')).toBe('/this/path/is/ok');
    });

    it('should preserve query parameters', () => {
      expect(AuthUtils.sanitizeReturnTo('/search?q=test')).toBe('/search?q=test');
      expect(AuthUtils.sanitizeReturnTo('/this/path?q=ok')).toBe('/this/path?q=ok');
      expect(AuthUtils.sanitizeReturnTo('/path?foo=bar&baz=qux')).toBe('/path?foo=bar&baz=qux');
    });

    it('should extract path from full URLs', () => {
      expect(AuthUtils.sanitizeReturnTo('https://example.com/path')).toBe('/path');
      expect(AuthUtils.sanitizeReturnTo('https://full-urls.are/not/allowed')).toBe('/not/allowed');
      expect(AuthUtils.sanitizeReturnTo('http://localhost:3000/dashboard')).toBe('/dashboard');
    });

    it('should extract path and query params from full URLs', () => {
      expect(AuthUtils.sanitizeReturnTo('https://example.com/search?q=test')).toBe('/search?q=test');
      expect(AuthUtils.sanitizeReturnTo('https://example.com/path?foo=bar&baz=qux')).toBe('/path?foo=bar&baz=qux');
    });

    it('should reject javascript: protocol', () => {
      expect(AuthUtils.sanitizeReturnTo('javascript:alert(1)')).toBeNull();
    });

    it('should reject other dangerous protocols', () => {
      expect(AuthUtils.sanitizeReturnTo('data:text/html,<script>alert(1)</script>')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo('vbscript:msgbox("xss")')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo('file:///etc/passwd')).toBeNull();
    });

    it('should reject protocol-relative URLs', () => {
      expect(AuthUtils.sanitizeReturnTo('//evil.com/path')).toBeNull();
    });

    it('should reject paths without leading slash', () => {
      expect(AuthUtils.sanitizeReturnTo('not-a-valid-path')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo('relative/path')).toBeNull();
    });

    it('should reject directory traversal attempts', () => {
      expect(AuthUtils.sanitizeReturnTo('/path/../../../etc/passwd')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo('/path/..%2F..%2Fetc/passwd')).toBeNull();
    });

    it('should handle empty and invalid inputs', () => {
      expect(AuthUtils.sanitizeReturnTo('')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo('   ')).toBeNull();
      expect(AuthUtils.sanitizeReturnTo(null as unknown as string)).toBeNull();
      expect(AuthUtils.sanitizeReturnTo(undefined as unknown as string)).toBeNull();
    });

    it('should handle root path', () => {
      expect(AuthUtils.sanitizeReturnTo('/')).toBe('/');
      expect(AuthUtils.sanitizeReturnTo('https://example.com/')).toBe('/');
      expect(AuthUtils.sanitizeReturnTo('https://example.com')).toBe('/');
    });
  });
});

describe('DefaultLogger', () => {
  let logger: DefaultLogger;
  let consoleSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new DefaultLogger(true); // verbose mode
    consoleSpy = jest.spyOn(console, 'log').mockImplementation();
  });

  afterEach(() => {
    consoleSpy.mockRestore();
  });

  it('should log structured messages', () => {
    logger.info('Test message', { key: 'value' });

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"level":"info"')
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"message":"Test message"')
    );
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('"key":"value"')
    );
  });

  it('should redact sensitive information', () => {
    logger.info('Test message', {
      password: 'secret123',
      token: 'abc123',
      publicInfo: 'visible'
    });

    const logCall = consoleSpy.mock.calls[0][0];
    expect(logCall).toContain('[REDACTED]');
    expect(logCall).toContain('visible');
    expect(logCall).not.toContain('secret123');
    expect(logCall).not.toContain('abc123');
  });

  it('should not log debug messages in non-verbose mode', () => {
    const nonVerboseLogger = new DefaultLogger(false);
    nonVerboseLogger.debug('Debug message');

    expect(consoleSpy).not.toHaveBeenCalled();
  });
});

describe('SAMLProvider', () => {
  it('should throw error for missing required config', () => {
    // Temporarily clear environment variables to test validation
    const originalEntity = process.env.ADAPT_AUTH_SAML_ENTITY;
    const originalCert = process.env.ADAPT_AUTH_SAML_CERT;

    delete process.env.ADAPT_AUTH_SAML_ENTITY;
    delete process.env.ADAPT_AUTH_SAML_CERT;

    expect(() => {
      new SAMLProvider({} as never);
    }).toThrow('Missing required SAML configuration');

    // Restore environment variables
    if (originalEntity) process.env.ADAPT_AUTH_SAML_ENTITY = originalEntity;
    if (originalCert) process.env.ADAPT_AUTH_SAML_CERT = originalCert;
  });

  it('should initialize with valid config', () => {
    const provider = new SAMLProvider({
      issuer: 'test-issuer',
      idpCert: 'test-cert',
      additionalParams: {},
      additionalAuthorizeParams: {},
    } as any);

    expect(provider).toBeInstanceOf(SAMLProvider);
  });
});

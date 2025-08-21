/* eslint-disable @typescript-eslint/no-explicit-any */
import { SAMLProvider } from '../src/saml';
import { AuthError } from '../src/types';
import { DefaultLogger } from '../src/logger';
import type { SAMLProfile, SamlConfig, AuthenticateOptions } from '../src/types';

// Mock Web API Request
global.Request = jest.fn().mockImplementation((input, init) => ({
  text: jest.fn(),
  ...init,
}));

interface MockRequest {
  text: () => Promise<string>;
}

describe('SAMLProvider', () => {
  const validConfig: SamlConfig = {
    issuer: 'test-issuer',
    idpCert: 'test-certificate',
    returnToOrigin: 'https://app.example.com',
    serviceProviderLoginUrl: 'https://idp.example.com/sso',
    returnToPath: '/auth/callback',
  };

  const logger = new DefaultLogger();

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('constructor', () => {
    test('should create SAMLProvider with valid config', () => {
      const provider = new SAMLProvider(validConfig, logger);
      expect(provider).toBeInstanceOf(SAMLProvider);
    });

    test('should throw AuthError for missing required config when no env vars', () => {
      // Clear environment variables
      const originalIssuer = process.env.ADAPT_AUTH_SAML_ENTITY;
      const originalCert = process.env.ADAPT_AUTH_SAML_CERT;
      const originalOrigin = process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN;

      delete process.env.ADAPT_AUTH_SAML_ENTITY;
      delete process.env.ADAPT_AUTH_SAML_CERT;
      delete process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN;

      expect(() => {
        new SAMLProvider({} as SamlConfig, logger);
      }).toThrow(AuthError);

      // Restore environment variables
      if (originalIssuer) process.env.ADAPT_AUTH_SAML_ENTITY = originalIssuer;
      if (originalCert) process.env.ADAPT_AUTH_SAML_CERT = originalCert;
      if (originalOrigin) process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN = originalOrigin;
    });

    test('should throw AuthError for missing issuer when no env vars', () => {
      const originalIssuer = process.env.ADAPT_AUTH_SAML_ENTITY;
      delete process.env.ADAPT_AUTH_SAML_ENTITY;

      const invalidConfig = { ...validConfig };
      delete (invalidConfig as Partial<SamlConfig>).issuer;

      expect(() => {
        new SAMLProvider(invalidConfig, logger);
      }).toThrow(AuthError);

      if (originalIssuer) process.env.ADAPT_AUTH_SAML_ENTITY = originalIssuer;
    });

    test('should throw AuthError for missing idpCert when no env vars', () => {
      const originalCert = process.env.ADAPT_AUTH_SAML_CERT;
      delete process.env.ADAPT_AUTH_SAML_CERT;

      const invalidConfig = { ...validConfig };
      delete (invalidConfig as Partial<SamlConfig>).idpCert;

      expect(() => {
        new SAMLProvider(invalidConfig, logger);
      }).toThrow(AuthError);

      if (originalCert) process.env.ADAPT_AUTH_SAML_CERT = originalCert;
    });
  });

  describe('getLoginUrl', () => {
    test('should generate login URL with returnTo', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const result = await provider.getLoginUrl({ returnTo: 'https://app.example.com/dashboard' });

      expect(result).toContain(validConfig.serviceProviderLoginUrl);
      expect(result).toContain('final_destination=https%3A%2F%2Fapp.example.com%2Fdashboard');
    });

    test('should generate login URL without returnTo', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const result = await provider.getLoginUrl();

      expect(result).toContain(validConfig.serviceProviderLoginUrl);
      // Check for the entity parameter - could be from env var or config
      expect(result).toMatch(/entity=(test-issuer|test-entity)/);
    });

    test('should include custom additional params', async () => {
      const provider = new SAMLProvider(validConfig, logger);
      const result = await provider.getLoginUrl({
        returnTo: '/dashboard',
        customParam: 'value'
      });

      expect(result).toContain('customParam=value');
    });
  });

  describe('authenticate', () => {
    test('should authenticate valid SAML response', async () => {
      const mockProfile: SAMLProfile = {
        issuer: 'test-issuer',
        sessionIndex: 'session-123',
        nameID: 'user@example.com',
        nameIDFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        'oracle:cloud:identity:sessionid': 'session-123',
        encodedSUID: 'encoded-suid-123',
        'oracle:cloud:identity:url': 'https://oracle.stanford.edu',
        userName: 'testuser',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock the SAML provider's validatePostResponseAsync method
      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: mockProfile,
      });

      const provider = new SAMLProvider(validConfig, logger);
      // Replace the provider's validatePostResponseAsync method
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      // Mock request with proper Request interface
      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response&RelayState=relay-state')
      } as MockRequest;

      // Add instanceof check support
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      const result = await provider.authenticate(options);

      expect(mockValidateResponse).toHaveBeenCalledWith({
        SAMLResponse: 'encoded-response',
      });
      expect(result.profile).toEqual(mockProfile);
      expect(result.user).toEqual({
        id: mockProfile.encodedSUID,
        email: `${mockProfile.userName}@stanford.edu`,
        name: `${mockProfile.firstName} ${mockProfile.lastName}`,
        imageUrl: undefined,
        suid: mockProfile.suid,
        encodedSUID: mockProfile.encodedSUID,
        userName: mockProfile.userName,
        firstName: mockProfile.firstName,
        lastName: mockProfile.lastName,
        sessionId: mockProfile['oracle:cloud:identity:sessionid'],
      });
    });

    test('should handle authentication errors', async () => {
      const mockValidateResponse = jest.fn().mockRejectedValue(new Error('Invalid SAML response'));

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=invalid-response')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });

    test('should handle missing SAML response', async () => {
      const provider = new SAMLProvider(validConfig, logger);

      const mockReq = {
        text: jest.fn().mockResolvedValue('')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });

    test('should handle missing profile in response', async () => {
      const mockValidateResponse = jest.fn().mockResolvedValue({
        profile: null,
      });

      const provider = new SAMLProvider(validConfig, logger);
      (provider as any).provider = {
        validatePostResponseAsync: mockValidateResponse,
      };

      const mockReq = {
        text: jest.fn().mockResolvedValue('SAMLResponse=encoded-response')
      } as MockRequest;
      Object.setPrototypeOf(mockReq, Request.prototype);

      const options: AuthenticateOptions = {
        req: mockReq as any,
      };

      await expect(provider.authenticate(options)).rejects.toThrow(AuthError);
    });
  });

  describe('getConfig', () => {
    test('should return SAML configuration', () => {
      const provider = new SAMLProvider(validConfig, logger);
      const config = provider.getConfig();

      // Test that the config contains all the expected fields with proper types
      expect(config.issuer).toBe(validConfig.issuer);
      expect(config.returnToOrigin).toBe(validConfig.returnToOrigin);
      expect(config.returnToPath).toBe(validConfig.returnToPath);
      expect(config.serviceProviderLoginUrl).toBe(validConfig.serviceProviderLoginUrl);
      expect(typeof config.acceptedClockSkewMs).toBe('number');
      expect(typeof config.wantAssertionsSigned).toBe('boolean');
      expect(typeof config.includeReturnTo).toBe('boolean');
    });
  });
});
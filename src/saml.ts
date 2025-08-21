import { SAML, SamlConfig as NodeSamlConfig } from '@node-saml/node-saml';
import {
  SamlConfig,
  SAMLProfile,
  SAMLResponse,
  LoginOptions,
  AuthenticateOptions,
  User,
  Logger,
  RelayStatePayload,
  AuthError,
} from './types';
import { AuthUtils } from './utils';
import { DefaultLogger } from './logger';

/**
 * SAML authentication provider for Stanford WebAuth
 */
export class SAMLProvider {
  private provider: SAML;
  private config: Required<SamlConfig>;
  private logger: Logger;

  constructor(config: SamlConfig, logger?: Logger) {
    this.logger = logger || new DefaultLogger();

    // Build configuration with defaults and environment variable fallbacks
    const samlConfig = {
      // Required fields (must be provided)
      issuer: config.issuer || process.env.ADAPT_AUTH_SAML_ENTITY,
      idpCert: config.idpCert || process.env.ADAPT_AUTH_SAML_CERT,
      returnToOrigin: config.returnToOrigin || process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN,

      // Optional fields with sensible defaults
      audience: config.audience || `https://${config.issuer || process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat'}.stanford.edu`,
      privateKey: config.privateKey || process.env.ADAPT_AUTH_SAML_PRIVATE_KEY || config.idpCert || process.env.ADAPT_AUTH_SAML_CERT || '',
      decryptionPvk: config.decryptionPvk || process.env.ADAPT_AUTH_SAML_DECRYPTION_KEY || '',

      // Service provider configuration with defaults
      serviceProviderLoginUrl: config.serviceProviderLoginUrl || process.env.ADAPT_AUTH_SAML_SP_URL || `https://${config.issuer || process.env.ADAPT_AUTH_SAML_ENTITY}.stanford.edu/api/sso/login`,
      returnToPath: config.returnToPath || process.env.ADAPT_AUTH_SAML_RETURN_PATH || '',

      // RelayState configuration with defaults
      includeReturnTo: config.includeReturnTo ?? true,

      // SAML protocol settings with secure defaults
      signatureAlgorithm: config.signatureAlgorithm || 'sha256',
      identifierFormat: config.identifierFormat || 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      allowCreate: config.allowCreate ?? false,
      wantAssertionsSigned: config.wantAssertionsSigned ?? true,
      wantAuthnResponseSigned: config.wantAuthnResponseSigned ?? true,
      acceptedClockSkewMs: config.acceptedClockSkewMs ?? 60000,

      // Additional parameters with defaults
      additionalParams: config.additionalParams || {},
      additionalAuthorizeParams: config.additionalAuthorizeParams || {},

      // Hardcoded callback URL (managed by SP middleware)
      callbackUrl: 'https://adapt-sso-uat.stanford.edu/api/sso/auth',
    };

    // Store the merged configuration
    this.config = samlConfig as Required<SamlConfig>;

    // Validate required configuration
    this.validateConfig();

    // Create SAML provider with compatible config
    const nodesamlConfig = {
      issuer: samlConfig.issuer,
      idpCert: samlConfig.idpCert,
      audience: samlConfig.audience,
      privateKey: samlConfig.privateKey,
      decryptionPvk: samlConfig.decryptionPvk,
      identifierFormat: samlConfig.identifierFormat,
      wantAssertionsSigned: samlConfig.wantAssertionsSigned,
      wantAuthnResponseSigned: samlConfig.wantAuthnResponseSigned,
      acceptedClockSkewMs: samlConfig.acceptedClockSkewMs,
      allowCreate: samlConfig.allowCreate,
      callbackUrl: samlConfig.callbackUrl,
      // Convert additionalParams to strings for node-saml compatibility
      additionalParams: Object.fromEntries(
        Object.entries(samlConfig.additionalParams).map(([k, v]) => [k, String(v)])
      ),
      additionalAuthorizeParams: Object.fromEntries(
        Object.entries(samlConfig.additionalAuthorizeParams).map(([k, v]) => [k, String(v)])
      ),
    };

    this.provider = new SAML(nodesamlConfig as NodeSamlConfig);

    this.logger.debug('SAML provider initialized', {
      issuer: this.config.issuer,
      audience: this.config.audience,
      serviceProviderLoginUrl: this.config.serviceProviderLoginUrl,
      returnToOrigin: this.config.returnToOrigin,
    });
  }

  private validateConfig(): void {
    const required = ['issuer', 'idpCert'];
    const missing = required.filter(key => {
      const value = this.config[key as keyof SamlConfig];
      return !value || (typeof value === 'string' && value.trim() === '');
    });

    if (missing.length > 0) {
      throw new AuthError(
        `Missing required SAML configuration: ${missing.join(', ')}`,
        'INVALID_CONFIG',
        400
      );
    }
  }

  /**
   * Generate login URL for SAML authentication
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    try {
      const { returnTo, ...additionalParams } = options;

      // Create RelayState payload if needed
      let relayState: string | undefined;
      if (this.config.includeReturnTo && returnTo) {
        const payload: RelayStatePayload = {
          return_to: returnTo || this.config.returnToPath || '/',
        };

        relayState = JSON.stringify(payload);
      }

      // Build service provider login URL
      const acsUrl = new URL(this.config.returnToPath, this.config.returnToOrigin).toString();
      const params = new URLSearchParams({
        entity: process.env.SAML_ENTITY_ID || this.config.issuer,
        return_to: acsUrl,
        final_destination: returnTo || this.config.returnToPath || '/',
        ...(relayState && { RelayState: relayState }),
        ...additionalParams,
      });

      const loginUrl = `${this.config.serviceProviderLoginUrl}?${params.toString()}`;

      this.logger.debug('Generated login URL', {
        hasRelayState: !!relayState,
        return_to: acsUrl,
        final_destination: returnTo || this.config.returnToPath || '/',
        loginUrl: loginUrl.split('?')[0], // Log URL without parameters for security
      });

      return loginUrl;
    } catch (error) {
      this.logger.error('Failed to generate login URL', {
        error: error instanceof Error ? error.message : 'Unknown error',
        options
      });
      throw error;
    }
  }

  /**
   * Initiate SAML login by redirecting to IdP
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    const loginUrl = await this.getLoginUrl(options);
    this.logger.debug('Generated login URL:', { loginUrl });
    return Response.redirect(loginUrl, 302);
  }

  /**
   * Authenticate SAML response from IdP
   */
  async authenticate(options: AuthenticateOptions): Promise<{
    user: User;
    profile: SAMLProfile;
    returnTo?: string;
  }> {
    const { req, callbacks } = options;

    try {
      // Validate request
      if (!req || !(req instanceof Request)) {
        throw new AuthError('Invalid request object provided', 'INVALID_REQUEST', 400);
      }

      // Extract SAML response from request body
      const requestText = await req.text();
      if (!requestText) {
        throw new AuthError('No request body found', 'MISSING_BODY', 400);
      }

      // Parse form data
      const formData = new URLSearchParams(requestText);
      const samlResponse = formData.get('SAMLResponse');
      const relayState = formData.get('RelayState');

      if (!samlResponse) {
        throw new AuthError('No SAMLResponse found in request', 'MISSING_SAML_RESPONSE', 400);
      }

      this.logger.debug('Received SAML response', {
        hasRelayState: !!relayState,
        samlResponseLength: samlResponse.length,
      });

      // Validate SAML response
      const result = await this.provider.validatePostResponseAsync({
        SAMLResponse: samlResponse
      }) as SAMLResponse;

      if (!result || !result.profile) {
        throw new AuthError('Invalid SAML response or missing profile', 'INVALID_SAML_RESPONSE', 400);
      }

      const profile = result.profile as SAMLProfile;

      this.logger.info('SAML authentication successful', {
        nameID: profile.nameID,
        issuer: profile.issuer,
        sessionIndex: profile.sessionIndex,
      });

      // Process RelayState to get returnTo URL
      let returnTo: string | undefined;
      if (relayState) {
        returnTo = await this.processRelayState(relayState);
      }

      // Map SAML profile to User object
      let user: User;
      if (callbacks?.mapProfile) {
        user = await callbacks.mapProfile(profile);
      } else {
        user = this.defaultMapProfile(profile);
      }

      // Call signIn callback if provided
      if (callbacks?.signIn) {
        await callbacks.signIn({ user, profile });
      }

      this.logger.info('User authentication completed', {
        userId: user.id,
        returnTo,
      });

      return { user, profile, returnTo };

    } catch (error) {
      this.logger.error('SAML authentication failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (error instanceof AuthError) {
        throw error;
      }

      throw new AuthError(
        'SAML authentication failed',
        'AUTHENTICATION_FAILED',
        500
      );
    }
  }

  /**
   * Process RelayState to extract returnTo URL
   */
  private async processRelayState(relayState: string): Promise<string | undefined> {
    try {
      // Parse RelayState as simple JSON
      const payload: RelayStatePayload = JSON.parse(relayState);

      // Sanitize return_to URL
      if (payload.return_to) {
        const allowedOrigins = [this.config.returnToOrigin];
        const sanitized = AuthUtils.sanitizeReturnTo(payload.return_to, allowedOrigins);

        if (!sanitized) {
          this.logger.warn('Return_to URL failed sanitization', { return_to: payload.return_to });
          return '/';
        }

        return sanitized;
      }

      return undefined;

    } catch (error) {
      this.logger.error('Failed to process RelayState', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return undefined;
    }
  }

  /**
   * Default mapping from SAML profile to User
   */
  private defaultMapProfile(profile: SAMLProfile): User {
    // Extract user information from Stanford SAML attributes
    const attributes = profile.attributes || profile;

    return {
      id: attributes.encodedSUID || profile.nameID || '',
      email: `${attributes.userName || profile.nameID}@stanford.edu`,
      name: [attributes.firstName, attributes.lastName].filter(Boolean).join(' ') || attributes.userName || profile.nameID || '',
      imageUrl: undefined,
      // Include additional Stanford-specific attributes
      suid: attributes.suid,
      encodedSUID: attributes.encodedSUID,
      userName: attributes.userName,
      firstName: attributes.firstName,
      lastName: attributes.lastName,
      sessionId: attributes['oracle:cloud:identity:sessionid'],
    };
  }

  /**
   * Get SAML provider configuration (for debugging)
   */
  getConfig(): Record<string, unknown> {
    // Return config without sensitive data
    const { privateKey, decryptionPvk, idpCert, ...safeConfig } = this.config;
    return {
      ...safeConfig,
      hasPrivateKey: !!privateKey,
      hasDecryptionKey: !!decryptionPvk,
      hasCert: !!idpCert,
    };
  }
}

/**
 * Create and configure a default SAML provider instance
 */
export function createSAMLProvider(config?: Partial<SamlConfig>, logger?: Logger): SAMLProvider {
  const defaultConfig = {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat',
    idpCert: process.env.ADAPT_AUTH_SAML_CERT || '',
    additionalParams: {},
    additionalAuthorizeParams: {},
    ...config,
  };

  return new SAMLProvider(defaultConfig as SamlConfig, logger);
}

// Export the SAML provider class as the main export
export { SAMLProvider as default };
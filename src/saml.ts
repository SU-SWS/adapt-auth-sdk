import { type SamlConfig } from './types'
import { SAML } from '@node-saml/node-saml'

/**
 * LoginOptions defines the options for the login method in AdaptAuth.
 */
export type LoginOptions = {
  /**
   * The destination URL to redirect to after login.
   * If not provided, defaults to '/'.
   */
  destination?: string;
};

/**
 * AuthenticateOptions defines the options for the authenticate method in AdaptAuth.
 */
export type AuthenticateOptions = {
  /**
   * The request object containing the SAML authentication response.
   * This is typically the HTTP request that contains the SAML assertion.
   */
  req: Request;
};

/**
 * AdaptAuth class provides methods for handling authentication.
 * It is designed to work with OIDCS SAML-based authentication systems.
 */
export class AdaptAuth {

  private provider: SAML;
  private relayState?: string | null;

  /**
   * Configuration for SAML authentication.
   */
  private saml: SamlConfig = {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat',
    audience: `https://${process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat'}.stanford.edu`,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT || 'you-must-pass-cert',
    privateKey: process.env.ADAPT_AUTH_SAML_CERT || 'you-must-pass-cert',
    decryptionPvk: process.env.ADAPT_AUTH_SAML_DECRYPTION_KEY || 'you-must-pass-decryption-key',
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN || 'http://localhost:3000/api/auth/acs',
    returnToPath: process.env.ADAPT_AUTH_SAML_RETURN_PATH || '',
    serviceProviderLoginUrl: process.env.ADAPT_AUTH_SAML_SP_URL || `https://${process.env.ADAPT_AUTH_SAML_ENTITY}.stanford.edu/api/sso/login`,
    signatureAlgorithm: 'sha256',
    additionalParams: {},
    additionalAuthorizeParams: {},
    identifierFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
    allowCreate: false,
    wantAssertionsSigned: true,
    wantAuthnResponseSigned: true,
    acceptedClockSkewMs: 60000, // 1 minute
    callbackUrl: 'https://adapt-sso-uat.stanford.edu/api/sso/auth', // Hard coded as the SP middleware will handle this setting once it gets there.
  } as SamlConfig;

  /**
   * Default constructor
   */
  constructor(options?: Partial<SamlConfig>) {
    if (options) {
      // Remove callbackUrl as it is set to a hardcoded value by setting it to undefined
      delete options.callbackUrl;
      this.saml = { ...this.saml, ...options };
    }

    this.provider = new SAML(this.saml);

    console.log('AdaptAuth initialized');
  }

  /**
   * Login method to handle user login
   * This method redirects the user to the service provider's login URL.
   */
  public login(options?: LoginOptions): Response {
    const { destination } = options || {};
    // Return a Response with a redirect to the service provider login URL
    const parms = new URLSearchParams({
      entity: this.saml.issuer,
      returnTo: this.saml.returnToOrigin!,
      final_destination: destination || '/',
    });
    const URL = this.saml.serviceProviderLoginUrl || `https://${this.saml.issuer}.stanford.edu/api/sso/login`;
    console.log(`Redirecting to SAML login URL: ${URL}?${parms.toString()}`);

    return Response.redirect(`${URL}?${parms.toString()}`, 302);
  }

  /**
   * Helper to get the service provider login URL
   * This URL is used to redirect users to the SAML service provider for authentication.
   */
  public getLoginUrl() {
    // Return the service provider login URL
    return this.saml.serviceProviderLoginUrl;
  }

  /**
   * Logout method to handle user logout
   * This is a placeholder for the actual logout logic
   */
  public logout() {
    console.log('Logout method called');
    // Implement logout logic here
  }

  /**
   * Helper to extract the saml relay state from a Request object
   */
  public getUser() {
    console.log('Get user method called');
    // Implement user retrieval logic here
  }

  /**
   * Authenticate method to handle user authentication
   * This is a placeholder for the actual authentication logic
   *
   * @returns {boolean} - Returns false by default, indicating no user is authenticated.
   */
  public async authenticate({ req }: AuthenticateOptions): Promise<any> {
    console.log('Authenticate method called');
    // Extract the SAML response from the request
    const responseText = await req.text();
    const SAMLResponse = new URLSearchParams(responseText).get('SAMLResponse') || null;
    this.relayState = new URLSearchParams(responseText).get('RelayState') || null;

    console.log('Extracting SAML response from request:', SAMLResponse);
    if (!SAMLResponse) {
      console.error('No SAML response found in the request');
      return null; // No SAML response, cannot authenticate
    }

    // Log if a decryption key is configured, as node-saml will use it for internal decryption
    if (this.saml.decryptionPvk) {
      console.log('Decryption private key is configured. node-saml will attempt to decrypt EncryptedAssertion if present.');
    } else {
      console.warn('No decryption private key configured. EncryptedAssertions will not be decrypted by node-saml.');
    }


    // Validate the SAML response
    let result;
    try {
      result = await this.provider.validatePostResponseAsync({ SAMLResponse });
      console.log('SAML response validated successfully:', result);
    } catch (error) {
      console.error('Error validating SAML response:', error);
      return null; // Validation failed
    }

    return result;
  }

  /**
   * Helper to extract the saml relay final destination url from a Request object
   */
  public getFinalDestination = (req: Request) => {
  //   // Attach relayState to req
  //   try {
  //     const relayState = req.samlRelayState;
  //     const finalDest = relayState.finalDestination || null;
  //     return finalDest;

  //   } catch (err) {
  //     // I guess the relayState wasn't that great...
  //     console.log('Unable to parse samlRelayState', err);
  //   }
  // };
    console.log('Getting final destination from request:', req);
  }
}

export const auth = new AdaptAuth();

export default auth;
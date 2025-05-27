import { SessionConfig, type AdaptAuthOptions, type SamlConfig } from './types'
import { ServiceProvider, ServiceProviderInstance } from 'samlify';

/**
 * LoginOptions defines the options for the login method in AdaptAuth.
 */
export type LoginOptions = {
  /**
   * The destination URL to redirect to after login.
   * If not provided, defaults to '/'.
   */
  destination?: string;
  /**
   * The relay state to include in the SAML authentication request.
   * This can be used to maintain state between the authentication request and the response.
   */
  relayState?: string;
};

/**
 * AdaptAuth class provides methods for handling authentication, session management, and user retrieval.
 * It is designed to work with OIDCS SAML-based authentication systems.
 */
export class AdaptAuth {

  /**
   * Configuration for SAML authentication.
   */
  private saml: SamlConfig = {
    entityID: process.env.ADAPT_AUTH_SAML_ENTITY || 'adapt-sso-uat',
    authnRequestsSigned: true,
    wantAssertionsSigned: true,
    privateKey: process.env.ADAPT_AUTH_SAML_CERT || 'you-must-pass-private-key',
    isAssertionEncrypted: true,
    requestSignatureAlgorithm: 'sha256',
    encPrivateKey: process.env.ADAPT_AUTH_SAML_DECRYPTION_KEY || 'you-must-pass-enc-private-key',
    assertionConsumerService: [{
      Binding: 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
      Location: `https://${process.env.ADAPT_AUTH_SAML_ENTITY}.stanford.edu/api/sso/auth`,
    }],
    signingCert: process.env.ADAPT_AUTH_SAML_CERT || 'you-must-pass-signing-cert',
    encryptCert: process.env.ADAPT_AUTH_SAML_DECRYPTION_KEY || 'you-must-pass-encrypt-cert',
    nameIDFormat: ['urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'],
    relayState: '',
    serviceProviderLoginUrl: process.env.ADAPT_AUTH_SAML_LOGIN_URL || `https://${process.env.ADAPT_AUTH_SAML_ENTITY}.stanford.edu/api/sso/login`,
    returnTo: process.env.ADAPT_AUTH_SAML_RETURN_URL || 'http://localhost:3000',
  };

  /**
   * Configuration for session management.
   */
  private session: SessionConfig = {
    secret: process.env.ADAPT_AUTH_SESSION_SECRET || '',
    name: process.env.ADAPT_AUTH_SESSION_NAME || 'adapt-auth',
    expiresIn: parseInt(process.env.ADAPT_AUTH_SESSION_EXPIRES_IN || '', 10) || 3600, // Default session expiration time (1 hour)
  };

  /**
   * Instance of the SAML service provider.
   * This is initialized with the samlify library to handle SAML authentication.
   */
  private provider: ServiceProviderInstance;

  /**
   * Default constructor
   */
  constructor(options?: AdaptAuthOptions) {
    if (options) {
      this.saml = { ...this.saml, ...options.saml };
      this.session = { ...this.session, ...options.session };
    }

    // Initialize SAML with the provided configuration
    this.provider = ServiceProvider(this.saml);

    console.log('AdaptAuth initialized');
  }

  /**
   * Login method to handle user login
   * This method redirects the user to the service provider's login URL.
   */
  public login(options?: LoginOptions): Response {
    const { destination, relayState } = options || {};
    console.log('Login method called');
    // Return a Response with a redirect to the service provider login URL
    const parms = new URLSearchParams({
      entity: this.saml.entityID!,
      returnTo: this.saml.returnTo!,
      final_destination: destination || '/',
      relayState: relayState || this.saml.relayState || '',
    });
    const URL = this.saml.serviceProviderLoginUrl || `https://${this.saml.entityID}.stanford.edu/api/sso/login`;
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
  public getSession() {
    console.log('Get session method called');
    // Implement session retrieval logic here
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
   */
  public authenticate() {
    console.log('Authenticate method called');
    // Implement authentication logic here
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
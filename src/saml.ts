import { type SamlConfig } from './types'
import { SAML, type Profile } from '@node-saml/node-saml'

/**
 * LoginOptions defines the options for the login method in AdaptSAML.
 */
export type LoginOptions = {
  /**
   * The destination URL to redirect to after login.
   * If not provided, defaults to '/'.
   */
  destination?: string;
};

/**
 * AuthenticateOptions defines the options for the authenticate method in AdaptSAML.
 */
export type AuthenticateOptions = {
  /**
   * The request object containing the SAML authentication response.
   * This is typically the HTTP request that contains the SAML assertion.
   */
  req: Request;
};

export type SAMLResponseAttributes = {
  'oracle:cloud:identity:domain': string,
  firstName?: string,
  lastName?: string,
  'oracle:cloud:identity:sessionid': string,
  'oracle:cloud:identity:tenant': string,
  encodedSUID: string,
  suid?: string,
  'oracle:cloud:identity:url': string,
  userName: string
};

export type SAMLProfile = Profile & {
  inResponseTo: string,
  'oracle:cloud:identity:domain': string,
  firstName?: string,
  lastName?: string,
  'oracle:cloud:identity:sessionid': string,
  'oracle:cloud:identity:tenant': string,
  encodedSUID: string,
  suid?: string,
  'oracle:cloud:identity:url': string,
  userName: string,
  attributes?: SAMLResponseAttributes,
};

export type SAMLResponse = {
  profile?: SAMLProfile,
  loggedOut?: boolean
}

/**
 * AdaptSAML class provides methods for handling authentication.
 * It is designed to work with OIDCS SAML-based authentication systems.
 */
export class AdaptSAML {

  /**
   * The SAML provider instance used for handling SAML authentication.
   * This instance is created using the SAML configuration provided during the class instantiation.
   */
  private provider: SAML;
  /**
   * The relay state used to maintain state between the authentication request and response.
   * This is typically a string that contains the final destination after authentication.
   */
  private relayState?: string | null;
  /**
   * The SAML response payload containing the user's profile and authentication status.
   * This is populated after a successful authentication.
   */
  private payload?: SAMLResponse;
  /**
   * The user profile extracted from the SAML response.
   * This contains user-specific information such as name, email, and other attributes.
   */
  private user?: SAMLProfile;

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
    // Hard coded as the SP middleware here as it is required but it will change once it gets to the SP middleware site.
    callbackUrl: 'https://adapt-sso-uat.stanford.edu/api/sso/auth',
  } as SamlConfig;

  /**
   * Create and initialize the AdaptSAML instance with SAML configuration.
   * @param {Partial<SamlConfig>} options - Optional configuration to override default SAML settings.
   * If provided, these options will be merged with the default SAML configuration.
   * Note: The `callbackUrl` is intentionally omitted as it is set to a hardcoded value.
   *
   * @example
   * const auth = new AdaptSAML({
   *   issuer: 'my-custom-issuer',
   *   idpCert: 'my-custom-cert',
   *   returnToOrigin: 'https://myapp.com/auth/callback',
   *   serviceProviderLoginUrl: 'https://myapp.com/saml/login',
   * });
   */
  constructor(options?: Partial<SamlConfig>) {
    if (options) {
      // Remove callbackUrl as it is set to a hardcoded url intentionally.
      // The Middleware SP server will handle the callbackUrl by adding it to the request
      // based on the other request parameters being sent to it.
      delete options.callbackUrl;
      this.saml = { ...this.saml, ...options };
    }
    this.provider = new SAML(this.saml);
  }

  /**
   * Login method to handle user login
   * This method redirects the user to the service provider's login URL.
   *
   * @param {LoginOptions} options - Optional parameters for the login process.
   * This can include a destination URL to redirect to after login.
   * @return {Response} - Returns a Response object that redirects the user to the SAML service provider login URL.
   * @throws {Error} - Throws an error if called in a browser environment, as it should only be called in a server context.
   * @example
   * const response = auth.login({ destination: '/dashboard' });
   */
  public login(options?: LoginOptions): Response {
    const URL = this.getLoginUrl(options);
    return Response.redirect(URL, 302);
  }

  /**
   * Helper to get the service provider login URL
   * This URL is used to redirect users to the SAML service provider for authentication.
   *
   * @returns {string | null} - Returns the service provider login URL.
   */
  public getLoginUrl(options?: LoginOptions): string {
    const { destination } = options || {};
    // Return a Response with a redirect to the service provider login URL
    const parms = new URLSearchParams({
      entity: this.saml.issuer,
      returnTo: this.saml.returnToOrigin!,
      final_destination: destination || '/',
    });
    const URL = this.saml.serviceProviderLoginUrl || `https://${this.saml.issuer}.stanford.edu/api/sso/login`;
    return `${URL}?${parms.toString()}`;
  }

  /**
   * Helper to extract the saml relay state from a Request object
   *
   * @returns { SAMLProfile } - Returns the user profile extracted from the SAML response.
   */
  public getUser() {
    if (!this.user) {
      console.error('Called getUser before authenticate');
      throw new Error('User not authenticated. Please call authenticate first.');
    }
    return this.user;
  }

  /**
   * Authenticate method to handle user authentication.
   * This method processes the SAML response from the request and validates it.
   *
   * @param {AuthenticateOptions} options - The options for authentication, including the request object.
   * This request object should contain the SAML response in its body.
   *
   * @returns {boolean} - Returns false by default, indicating no user is authenticated.
   */
  public async authenticate({ req }: AuthenticateOptions): Promise<boolean> {

    // Validate the request object
    if (!req || !(req instanceof Request)) {
      console.error('Invalid request object provided for authentication');
      throw new Error('Invalid request object provided for authentication');
    }

    // Extract the SAML response from the request
    const responseText = await req.text();

    // Check if the response text is empty or undefined
    if (!responseText) {
      console.error('No response text found in the request');
      throw new Error('No response text found in the request');
    }

    // Parse the SAML response and relay state from the request body
    const SAMLResponse = new URLSearchParams(responseText).get('SAMLResponse') || null;
    this.relayState = new URLSearchParams(responseText).get('RelayState') || null;

    if (!SAMLResponse) {
      console.error('No SAML response found in the request');
      throw new Error('No SAML response found in the request');
    }

    // Validate and parse the SAML response.
    let result: SAMLResponse;
    try {
      result = await this.provider.validatePostResponseAsync({ SAMLResponse }) as SAMLResponse;
    } catch (error) {
      console.error('Error validating SAML response:', error);
      throw new Error('SAML response validation failed');
    }

    if (!result) {
      console.error('Nothing in the result of validatePostResponseAsync');
      throw new Error('SAML response is not valid or empty');
    }

    if (!result.profile) {
      console.error('No user profile found in the SAML response');
      return false;
    }

    this.payload = result;
    this.user = result.profile;

    return true;
  }

  /**
   * Get the SAML response payload
   * This method returns the SAML response payload after authentication.
   *
   * @returns {SAMLResponse} - The SAML response payload containing user profile and authentication status.
   * @throws {Error} - Throws an error if the payload is not available, indicating that authenticate must be called first.
   */
  public getSamlPayload() {
    if (!this.payload) {
      console.error('Called getSamlPayload before authenticate');
      throw new Error('Payload not available. Please call authenticate first.');
    }
    return this.payload;
  }

  /**
   * Helper to extract the saml relay final destination url from a Request object
   *
   * @returns {string} - Returns the final destination URL extracted from the relay state.
   * @throws {Error} - Throws an error if the relay state is not set or if the final destination is not found.
   */
  public getFinalDestination = () => {

    if (!this.relayState) {
      console.error('No relay state found. Please call authenticate first.');
      throw new Error('No relay state found. Please call authenticate first.');
    }

    // Parse relay state into json
    let json;
    try {
      json = JSON.parse(this.relayState);
    } catch (err) {
      console.log('Unable to parse relay state JSON', err);
      throw new Error('Invalid relay state format');
    }

    // Check if the final destination is present in the relay state
    if (json.finalDestination) {
      console.log('Final destination found in relay state:', json.finalDestination);
      return json.finalDestination;
    }

    console.warn('No final destination found in relay state');
    return '/'; // Default to root if no final destination is found
  }
}

/**
 * Create an instance of AdaptSAML to use in your application.
 * This instance can be used to call methods like login and authenticate.
 */
export const auth = new AdaptSAML();
export default auth;
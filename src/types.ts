import { type SamlOptions } from '@node-saml/node-saml';

/**
 * Configuration for SAML authentication in AdaptAuth.
 * This configuration is used to set up the SAML service provider that AdaptAuth will use for authentication.
 */
export type SamlConfig = SamlOptions & {
  /**
   * The URL to redirect users to for logging in via the service provider.
   * This URL exists at the service provider and is in the format of `https://<entityId>.stanford.edu/api/sso/login`.
   */
  serviceProviderLoginUrl?: string;

  /**
   * The URL address of the site to receive the SAML response from the SP middleware.
   */
  returnToOrigin?: string;

  /**
   * Return to path after login.
   * This is the path to which the user will be redirected after a successful login.
   */
  returnToPath?: string;

  /**
   * Optional relay state parameter.
   * This parameter can be used to maintain state between the authentication request and the response.
   */
  relayState?: string;
}

/**
 * Configuration for the session management in AdaptAuth.
 */
export type SessionConfig = {
  /**
   * The name of the session cookie.
   * This is used to identify the session in the user's browser.
   *
   * Example: 'adapt-auth-session'
   *
   * @type {string}
   */
  name: string;
  /**
   * The secret used to sign the session cookie.
   * This should be a strong, random string to ensure the security of the session.
   *
   * Example: 'supersecretkey'
   *
   * @type {string}
   */
  secret: string;
  /**
   * The duration in seconds for which the session is valid.
   * After this time, the session will expire and the user will need to log in again.
   *
   * Example: 3600 (1 hour)
   *
   * @type {number}
   */
  expiresIn: number;
};
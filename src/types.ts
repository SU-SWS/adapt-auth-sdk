import { ServiceProviderSettings } from "samlify/types/src/types";

/**
 * AdaptAuthOptions defines the configuration options for the AdaptAuth middleware.
 */
export type AdaptAuthOptions = Partial<{
  /**
   * Configuration for SAML authentication.
   * This is used to set up the SAML service provider that AdaptAuth will use for authentication.
   */
  saml: SamlConfig;
  /**
   * Configuration for session management.
   * This is used to manage user sessions, including session cookies and expiration.
   */
  session: SessionConfig;
}>;

/**
 * Configuration for SAML authentication in AdaptAuth.
 * This configuration is used to set up the SAML service provider that AdaptAuth will use for authentication.
 */
export type SamlConfig = ServiceProviderSettings & {
  /**
   * The URL to redirect users to for logging in via the service provider.
   * This URL exists at the service provider and is in the format of `https://<entityId>.stanford.edu/api/sso/login`.
   */
  serviceProviderLoginUrl?: string;

  /**
   * The URL address of the site to receive the SAML response from the SP middleware.
   */
  returnTo?: string;
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
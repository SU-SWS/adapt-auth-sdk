import { type SamlOptions } from '@node-saml/node-saml';

/**
 * User data structure for session storage
 */
export type User = {
  id: string;
  email?: string;
  name?: string;
  imageUrl?: string;
  [key: string]: unknown; // Allow additional user properties
};

/**
 * Session data structure
 */
export type Session = {
  user: User;
  meta?: Record<string, unknown>; // developer-defined metadata
  issuedAt: number;
  expiresAt: number;
};

/**
 * RelayState payload structure
 */
export type RelayStatePayload = {
  nonce: string;
  issuedAt: number;
  returnTo?: string;
};

/**
 * Structured logger interface
 */
export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Configuration for SAML authentication in AdaptAuth.
 */
export type SamlConfig = SamlOptions & {
  /**
   * The URL to redirect users to for logging in via the service provider.
   */
  serviceProviderLoginUrl?: string;

  /**
   * The URL address of the site to receive the SAML response from the SP middleware.
   */
  returnToOrigin?: string;

  /**
   * Return to path after login.
   */
  returnToPath?: string;

  /**
   * Whether to include returnTo URL in RelayState
   */
  includeReturnTo?: boolean;

  /**
   * Maximum age for RelayState validation in seconds
   */
  relayStateMaxAge?: number;

  /**
   * HMAC secret for RelayState signing
   */
  relayStateSecret?: string;
};

/**
 * Configuration for session management in AdaptAuth.
 */
export type SessionConfig = {
  /**
   * The name of the session cookie.
   */
  name: string;

  /**
   * The secret used to sign the session cookie.
   */
  secret: string;

  /**
   * Cookie configuration options
   */
  cookie?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'lax' | 'strict' | 'none';
    path?: string;
    domain?: string;
    maxAge?: number;
  };

  /**
   * Cookie size warning threshold in bytes
   */
  cookieSizeThreshold?: number;
};

/**
 * Authentication configuration
 */
export type AuthConfig = {
  saml: SamlConfig;
  session: SessionConfig;
  logger?: Logger;
  verbose?: boolean;
};

/**
 * Callbacks for customizing authentication behavior
 */
export type AuthCallbacks = {
  /**
   * Called after successful SAML authentication to map SAML profile to User
   */
  mapProfile?: (profile: SAMLProfile) => Promise<User> | User;

  /**
   * Called when creating/updating session to enrich session data
   */
  session?: (params: {
    session: Session;
    user: User;
    req: Request;
  }) => Promise<Session> | Session;

  /**
   * Called on authentication events
   */
  signIn?: (params: { user: User; profile: SAMLProfile }) => Promise<void> | void;
  signOut?: (params: { session: Session }) => Promise<void> | void;
};

/**
 * Login options
 */
export type LoginOptions = {
  returnTo?: string;
  [key: string]: unknown;
};

/**
 * Authentication options for ACS
 */
export type AuthenticateOptions = {
  req: Request;
  callbacks?: AuthCallbacks;
};

/**
 * Logout options
 */
export type LogoutOptions = {
  slo?: boolean; // Single Logout
  redirectTo?: string;
};

/**
 * SAML Response structure from Stanford
 */
export type SAMLResponseAttributes = {
  'oracle:cloud:identity:domain': string;
  firstName?: string;
  lastName?: string;
  'oracle:cloud:identity:sessionid': string;
  'oracle:cloud:identity:tenant': string;
  encodedSUID: string;
  suid?: string;
  'oracle:cloud:identity:url': string;
  userName: string;
  [key: string]: unknown;
};

/**
 * Extended SAML Profile with Stanford-specific attributes
 */
export type SAMLProfile = {
  inResponseTo?: string;
  issuer?: string;
  nameID?: string;
  nameIDFormat?: string;
  sessionIndex?: string;
  attributes?: SAMLResponseAttributes;
  [key: string]: unknown;
} & SAMLResponseAttributes;

/**
 * SAML Response result
 */
export type SAMLResponse = {
  profile?: SAMLProfile;
  loggedOut?: boolean;
};

/**
 * Error types
 */
export class AuthError extends Error {
  public code: string;
  public statusCode: number;

  constructor(message: string, code: string, statusCode = 500) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

/**
 * Context passed to route handlers
 */
export type AuthContext = {
  session?: Session;
  user?: User;
  isAuthenticated: boolean;
};

/**
 * Route handler type
 */
export type RouteHandler = (
  req: Request,
  context: AuthContext
) => Promise<Response> | Response;
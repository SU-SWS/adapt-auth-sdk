/**
 * Next.js integration for ADAPT Auth SDK
 * Provides simplified methods for authentication in Next.js applications
 */

import { SAMLProvider } from './saml';
import { SessionManager, CookieStore, CookieOptions } from './session';
import {
  RequiredSamlConfig,
  OptionalSamlConfig,
  RequiredSessionConfig,
  OptionalSessionConfig,
  SessionConfig,
  User,
  Session,
  LoginOptions,
  AuthCallbacks,
  Logger,
  AuthContext,
  RouteHandler
} from './types';
import { DefaultLogger } from './logger';

/**
 * Create a cookie store adapter for Next.js
 */
export function createNextjsCookieStore(cookies: unknown): CookieStore {
  const cookiesObj = cookies as { get: (name: string) => { name: string; value: string } | undefined; set: (name: string, value: string, options?: CookieOptions) => void };

  return {
    get: (name: string) => cookiesObj.get(name),
    set: (name: string, value: string, options?: CookieOptions) => {
      cookiesObj.set(name, value, options);
    },
    delete: (name: string) => {
      cookiesObj.set(name, '', { maxAge: 0 });
    },
  };
}

/**
 * Next.js specific edge session functions
 */
export async function getSessionFromNextRequest(
  request: Request,
  secret?: string,
  cookieName?: string
): Promise<Session | null> {
  const { createEdgeSessionReader } = await import('./edge-session');
  const reader = createEdgeSessionReader(secret, cookieName);
  return reader.getSessionFromRequest(request);
}

/**
 * Get session from Next.js cookies object
 */
export async function getSessionFromNextCookies(
  cookies: { get?: (name: string) => { value: string } | undefined },
  secret?: string,
  cookieName?: string
): Promise<Session | null> {
  const sessionSecret = secret ||
    (typeof process !== 'undefined' ? process.env?.ADAPT_AUTH_SESSION_SECRET : undefined);

  const sessionName = cookieName ||
    (typeof process !== 'undefined' ? process.env?.ADAPT_AUTH_SESSION_NAME : undefined) ||
    'adapt-auth-session';

  if (!sessionSecret) {
    throw new Error('Session secret is required. Provide it as parameter or set ADAPT_AUTH_SESSION_SECRET environment variable.');
  }

  if (!cookies.get) {
    return null;
  }

  const cookie = cookies.get(sessionName);
  if (!cookie) {
    return null;
  }

  // Import and use EdgeSessionReader for decryption
  const { EdgeSessionReader } = await import('./edge-session');
  const reader = new EdgeSessionReader(sessionSecret, sessionName);

  // Use the public decryptSession method directly
  return reader.decryptSession(cookie.value);
}

/**
 * Required configuration for AdaptNext (minimal fields developers must provide)
 */
export interface RequiredAdaptNextConfig {
  /**
   * SAML configuration - only required fields need to be provided
   */
  saml: RequiredSamlConfig;

  /**
   * Session configuration - only required fields need to be provided
   */
  session: RequiredSessionConfig;
}

/**
 * Optional configuration for AdaptNext with sensible defaults
 */
export interface OptionalAdaptNextConfig {
  /**
   * Optional SAML configuration (will use sensible defaults)
   */
  saml?: OptionalSamlConfig;

  /**
   * Optional session configuration (will use sensible defaults)
   */
  session?: OptionalSessionConfig;

  /**
   * Custom logger implementation
   * @default DefaultLogger
   */
  logger?: Logger;

  /**
   * Enable verbose logging for debugging
   * @default false
   */
  verbose?: boolean;

  /**
   * Authentication event callbacks
   */
  callbacks?: AuthCallbacks;
}

/**
 * Complete configuration for AdaptNext (combines required and optional)
 *
 * @example
 * ```typescript
 * // Minimal Next.js configuration
 * const auth = createAdaptNext({
 *   saml: {
 *     issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
 *     idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
 *     returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!
 *   },
 *   session: {
 *     name: 'adapt-auth-session',
 *     secret: process.env.ADAPT_AUTH_SESSION_SECRET!
 *   }
 * });
 * ```
 */
export type AdaptNextConfig = RequiredAdaptNextConfig & OptionalAdaptNextConfig;

/**
 * AdaptNext class for Next.js integration
 * Provides simplified methods for authentication in Next.js App Router
 */
export class AdaptNext {
  private samlProvider: SAMLProvider;
  private sessionConfig: SessionConfig;
  private logger: Logger;
  private callbacks?: AuthCallbacks;
  private _sessionManager: SessionManager | null = null;

  constructor(config: AdaptNextConfig) {
    this.logger = config.logger || new DefaultLogger(config.verbose);
    this.callbacks = config.callbacks;

    // Merge required and optional SAML config
    const samlConfig = {
      ...config.saml,
      ...(config.saml && 'serviceProviderLoginUrl' in config.saml ? {} : {}), // Handle overlap
    };

    // Merge required and optional session config
    this.sessionConfig = {
      ...config.session,
      ...(config.session && 'cookie' in config.session ? {} : {}), // Handle overlap
    };

    this.samlProvider = new SAMLProvider(samlConfig, this.logger);
  }

  /**
   * Check for browser environment and throw error if detected
   */
  private assertServerEnvironment(methodName: string): void {
    if (typeof window !== 'undefined') {
      throw new Error(`AdaptNext.${methodName}() should not be called in a browser environment`);
    }
  }

  /**
   * Get or create session manager with Next.js cookies (cached)
   */
  private async getSessionManager(): Promise<SessionManager> {
    // Dynamic import to avoid issues with Next.js server components
    const { cookies } = await import('next/headers');
    const cookieStore = createNextjsCookieStore(await cookies());

    // Create new instance each time since cookies() must be called fresh in Next.js
    return new SessionManager(cookieStore, this.sessionConfig, this.logger);
  }

  /**
   * Initiate SAML login
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    this.assertServerEnvironment('login');
    return this.samlProvider.login(options);
  }

  /**
   * Handle SAML authentication callback (ACS endpoint)
   */
  async authenticate(request: Request): Promise<{
    user: User;
    session: Session;
    returnTo?: string;
  }> {
    this.assertServerEnvironment('authenticate');

    // Authenticate with SAML (let SAMLProvider handle its own error logging)
    const { user, returnTo } = await this.samlProvider.authenticate({
      req: request,
      callbacks: this.callbacks,
    });

    // Create session (let SessionManager handle its own error logging)
    const sessionManager = await this.getSessionManager();
    const session = await sessionManager.createSession(user);

    // Call session callback if provided
    if (this.callbacks?.session) {
      await this.callbacks.session({ session, user, req: request });
    }

    return { user, session, returnTo };
  }

  /**
   * Get current session
   */
  async getSession(): Promise<Session | null> {
    this.assertServerEnvironment('getSession');
    const sessionManager = await this.getSessionManager();
    return sessionManager.getSession();
  }

  /**
   * Get current user
   */
  async getUser(): Promise<User | null> {
    this.assertServerEnvironment('getUser');
    const sessionManager = await this.getSessionManager();
    return sessionManager.getUser();
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    this.assertServerEnvironment('isAuthenticated');
    const sessionManager = await this.getSessionManager();
    return sessionManager.isAuthenticated();
  }

  /**
   * Logout and destroy session
   */
  async logout(): Promise<void> {
    this.assertServerEnvironment('logout');

    const sessionManager = await this.getSessionManager();

    // Get session for callback before destroying it
    const session = await sessionManager.getSession();
    if (session && this.callbacks?.signOut) {
      await this.callbacks.signOut({ session });
    }

    // Let SessionManager handle destruction and logging
    await sessionManager.destroySession();
  }

  /**
   * Middleware function for protecting routes
   */
  auth(handler: RouteHandler) {
    return async (request: Request): Promise<Response> => {
      const sessionManager = await this.getSessionManager();
      const session = await sessionManager.getSession();

      const context: AuthContext = {
        session: session || undefined,
        user: session?.user || undefined,
        isAuthenticated: !!session?.user,
      };

      return handler(request, context);
    };
  }

  /**
   * Create login URL without redirecting
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    return this.samlProvider.getLoginUrl(options);
  }

  /**
   * Refresh session (sliding expiration)
   */
  async refreshSession(): Promise<Session | null> {
    this.assertServerEnvironment('refreshSession');
    const sessionManager = await this.getSessionManager();
    return sessionManager.refreshSession();
  }

  /**
   * Update session with additional metadata
   * Convenience function to add custom data to the session cookie
   *
   * @param updates - Partial session data to update
   * @returns Updated session or null if no session exists
   *
   * @example
   * ```typescript
   * // Add user preferences to session
   * await auth.updateSession({
   *   meta: {
   *     theme: 'dark',
   *     language: 'en',
   *     lastVisited: '/dashboard'
   *   }
   * });
   *
   * // Add custom user data
   * await auth.updateSession({
   *   user: {
   *     ...currentUser,
   *     displayName: 'John Doe',
   *     avatar: '/images/avatar.jpg'
   *   }
   * });
   * ```
   */
  async updateSession(updates: Partial<Session>): Promise<Session | null> {
    this.assertServerEnvironment('updateSession');

    const sessionManager = await this.getSessionManager();
    const updatedSession = await sessionManager.updateSession(updates);

    // Call session callback if provided and session was updated
    if (updatedSession && this.callbacks?.session) {
      // Create a minimal request-like object for session callback
      const dummyRequest = new Request('http://localhost');
      await this.callbacks.session({
        session: updatedSession,
        user: updatedSession.user,
        req: dummyRequest
      });
    }

    return updatedSession;
  }
}

/**
 * Create an AdaptNext instance with configuration
 */
export function createAdaptNext(config: AdaptNextConfig): AdaptNext {
  return new AdaptNext(config);
}

// Export types for convenience
export { type AuthContext, type RouteHandler };

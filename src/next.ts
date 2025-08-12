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
  return reader['decryptSession'](cookie.value); // Access private method
}

/**
 * Convenience function for checking authentication in Next.js edge middleware
 */
export async function isAuthenticatedEdge(
  request: Request,
  secret?: string,
  cookieName?: string
): Promise<boolean> {
  const { createEdgeSessionReader } = await import('./edge-session');
  const reader = createEdgeSessionReader(secret, cookieName);
  return reader.isAuthenticated(request);
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
   * Create session manager with Next.js cookies
   */
  private async createSessionManager() {
    // Dynamic import to avoid issues with Next.js server components
    const { cookies } = await import('next/headers');
    const cookieStore = createNextjsCookieStore(await cookies());
    return new SessionManager(cookieStore, this.sessionConfig, this.logger);
  }

  /**
   * Initiate SAML login
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    this.logger.debug('Initiating SAML login', { options });

    // Check for browser environment
    if (typeof window !== 'undefined') {
      throw new Error('AdaptNext.login() should not be called in a browser environment');
    }

    return await this.samlProvider.login(options);
  }

  /**
   * Handle SAML authentication callback (ACS endpoint)
   */
  async authenticate(request: Request): Promise<{
    user: User;
    session: Session;
    returnTo?: string;
  }> {
    this.logger.debug('Processing SAML authentication');

    // Check for browser environment
    if (typeof window !== 'undefined') {
      throw new Error('AdaptNext.authenticate() should not be called in a browser environment');
    }

    try {
      // Authenticate with SAML
      const { user, returnTo } = await this.samlProvider.authenticate({
        req: request,
        callbacks: this.callbacks,
      });

      // Create session
      const sessionManager = await this.createSessionManager();
      const session = await sessionManager.createSession(user);

      // Call session callback if provided
      if (this.callbacks?.session) {
        await this.callbacks.session({ session, user, req: request });
      }

      this.logger.info('Authentication successful', {
        userId: user.id,
        returnTo,
      });

      return { user, session, returnTo };

    } catch (error) {
      this.logger.error('Authentication failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Get current session
   */
  async getSession(): Promise<Session | null> {
    // Check for browser environment
    if (typeof window !== 'undefined') {
      throw new Error('AdaptNext.getSession() should not be called in a browser environment');
    }

    try {
      const sessionManager = await this.createSessionManager();
      return await sessionManager.getSession();
    } catch (error) {
      this.logger.error('Failed to get session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }
  }

  /**
   * Get current user
   */
  async getUser(): Promise<User | null> {
    const session = await this.getSession();
    return session?.user || null;
  }

  /**
   * Check if user is authenticated
   */
  async isAuthenticated(): Promise<boolean> {
    const session = await this.getSession();
    return session !== null && !!session.user;
  }

  /**
   * Logout and destroy session
   */
  async logout(): Promise<void> {
    // Check for browser environment
    if (typeof window !== 'undefined') {
      throw new Error('AdaptNext.logout() should not be called in a browser environment');
    }

    try {
      const session = await this.getSession();

      if (session && this.callbacks?.signOut) {
        await this.callbacks.signOut({ session });
      }

      const sessionManager = await this.createSessionManager();
      await sessionManager.destroySession();

      this.logger.info('User logged out', {
        userId: session?.user?.id,
      });

    } catch (error) {
      this.logger.error('Logout failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Middleware function for protecting routes
   */
  auth(handler: RouteHandler) {
    return async (request: Request): Promise<Response> => {
      try {
        const session = await this.getSession();
        const context: AuthContext = {
          session: session || undefined,
          user: session?.user || undefined,
          isAuthenticated: !!session?.user,
        };

        return await handler(request, context);

      } catch (error) {
        this.logger.error('Auth middleware error', {
          error: error instanceof Error ? error.message : 'Unknown error',
        });

        // Return unauthorized response
        return new Response('Unauthorized', { status: 401 });
      }
    };
  }

  /**
   * Create login URL without redirecting
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    return await this.samlProvider.getLoginUrl(options);
  }

  /**
   * Refresh session (sliding expiration)
   */
  async refreshSession(): Promise<Session | null> {
    try {
      const sessionManager = await this.createSessionManager();
      return await sessionManager.refreshSession();
    } catch (error) {
      this.logger.error('Failed to refresh session', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      return null;
    }
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

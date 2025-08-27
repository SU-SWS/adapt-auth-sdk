/**
 * Next.js App Router integration for ADAPT Auth SDK
 *
 * This module provides simplified authentication methods specifically designed
 * for Next.js App Router applications. It wraps the core SAML and Session
 * functionality with Next.js-specific conveniences.
 *
 * Features:
 * - App Router compatible (uses next/headers cookies)
 * - Server Components and Server Actions support
 * - Route protection middleware
 * - Automatic session management
 * - TypeScript-first API design
 * - Environment validation
 *
 * The AdaptNext class provides a high-level interface that handles the
 * complexity of SAML authentication while providing familiar Next.js patterns.
 *
 * @module next
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
 *
 * Adapts the Next.js cookies() API to the generic CookieStore interface.
 * This allows the SessionManager to work with Next.js App Router cookies.
 *
 * @param cookies - Next.js cookies object from next/headers
 * @returns CookieStore implementation compatible with Next.js
 *
 * @example
 * ```typescript
 * import { cookies } from 'next/headers';
 *
 * const cookieStore = createNextjsCookieStore(await cookies());
 * const sessionManager = new SessionManager(cookieStore, config);
 * ```
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
 * Get session from Next.js Request object (for edge functions)
 *
 * Utility function for reading sessions in Next.js edge functions
 * where the full SessionManager might not be available.
 *
 * @param request - Next.js Request object
 * @param secret - Session secret (optional, uses env var)
 * @param cookieName - Session cookie name (optional, uses env var)
 * @returns Promise resolving to session data or null
 *
 * @example
 * ```typescript
 * // In middleware.ts
 * export async function middleware(request: NextRequest) {
 *   const session = await getSessionFromNextRequest(request);
 *   if (!session) {
 *     return NextResponse.redirect(new URL('/login', request.url));
 *   }
 *   return NextResponse.next();
 * }
 * ```
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
 *
 * Utility function for reading sessions directly from Next.js cookies.
 * Useful in Server Components and Server Actions.
 *
 * @param cookies - Next.js cookies object (must have get method)
 * @param secret - Session secret (optional, uses env var)
 * @param cookieName - Session cookie name (optional, uses env var)
 * @returns Promise resolving to session data or null
 *
 * @example
 * ```typescript
 * // In Server Component
 * import { cookies } from 'next/headers';
 *
 * export default async function Dashboard() {
 *   const session = await getSessionFromNextCookies(await cookies());
 *
 *   if (!session) {
 *     redirect('/login');
 *   }
 *
 *   return <div>Welcome {session.user.name}!</div>;
 * }
 * ```
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
 *
 * High-level authentication class designed specifically for Next.js App Router.
 * Provides a simple API that handles SAML authentication, session management,
 * and route protection.
 *
 * Key features:
 * - Server-side only (throws errors if used in browser)
 * - Integrates with Next.js App Router cookies
 * - Automatic SAML provider and session management
 * - Built-in error handling and logging
 * - TypeScript-first with comprehensive type safety
 * - Callback system for custom authentication logic
 *
 * @example
 * ```typescript
 * // Create auth instance
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
 *
 * // In route handlers
 * export async function GET() {
 *   return auth.login({ returnTo: '/dashboard' });
 * }
 *
 * export async function POST(request: Request) {
 *   const { user, returnTo } = await auth.authenticate(request);
 *   return Response.redirect(returnTo || '/dashboard');
 * }
 * ```
 */
export class AdaptNext {
  private samlProvider: SAMLProvider;
  private sessionConfig: SessionConfig;
  private logger: Logger;
  private callbacks?: AuthCallbacks;
  private _sessionManager: SessionManager | null = null;

  /**
   * Create a new AdaptNext instance
   *
   * Initializes SAML provider and configures session management for Next.js.
   * Merges provided configuration with sensible defaults.
   *
   * @param config - Authentication configuration (required and optional settings)
   *
   * @example
   * ```typescript
   * const auth = new AdaptNext({
   *   saml: {
   *     issuer: 'my-app-entity-id',
   *     idpCert: process.env.SAML_CERT,
   *     returnToOrigin: 'https://myapp.com'
   *   },
   *   session: {
   *     name: 'my-session',
   *     secret: process.env.SESSION_SECRET
   *   },
   *   verbose: true // Enable debug logging
   * });
   * ```
   */
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
   *
   * AdaptNext is designed for server-side use only. This method prevents
   * accidental usage in browser environments where it would fail.
   *
   * @param methodName - Name of the method being called (for error message)
   * @throws {Error} If called in browser environment
   * @private
   */
  private assertServerEnvironment(methodName: string): void {
    if (typeof window !== 'undefined') {
      throw new Error(`AdaptNext.${methodName}() should not be called in a browser environment`);
    }
  }

  /**
   * Get or create session manager with Next.js cookies (cached)
   *
   * Dynamically imports Next.js cookies to avoid issues with Server Components.
   * Creates a fresh SessionManager instance for each call.
   *
   * @returns Promise resolving to configured SessionManager
   * @private
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
   *
   * Redirects user to Stanford WebAuth for authentication.
   *
   * @param options - Login options including returnTo URL
   * @returns Promise resolving to redirect Response to IdP login page
   *
   * @example
   * ```typescript
   * // app/login/route.ts
   * export async function GET() {
   *   return auth.login({ returnTo: '/dashboard' });
   * }
   * ```
   */
  async login(options: LoginOptions = {}): Promise<Response> {
    this.assertServerEnvironment('login');
    return this.samlProvider.login(options);
  }

  /**
   * Handle SAML authentication callback (ACS endpoint)
   *
   * Processes the SAML response from Stanford WebAuth and creates a session.
   *
   * @param request - HTTP Request containing SAML response
   * @returns Promise resolving to authenticated user, session, and returnTo URL
   *
   * @throws {AuthError} If SAML authentication fails
   *
   * @example
   * ```typescript
   * // app/auth/acs/route.ts
   * export async function POST(request: Request) {
   *   try {
   *     const { user, returnTo } = await auth.authenticate(request);
   *     return Response.redirect(returnTo || '/dashboard');
   *   } catch (error) {
   *     return Response.redirect('/login?error=auth_failed');
   *   }
   * }
   * ```
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
   *
   * @returns Promise resolving to current session or null if not authenticated
   *
   * @example
   * ```typescript
   * // In Server Component or Server Action
   * const session = await auth.getSession();
   * if (session) {
   *   console.log('User:', session.user.name);
   * }
   * ```
   */
  async getSession(): Promise<Session | null> {
    this.assertServerEnvironment('getSession');
    const sessionManager = await this.getSessionManager();
    return sessionManager.getSession();
  }

  /**
   * Get current user
   *
   * @returns Promise resolving to current user or null if not authenticated
   *
   * @example
   * ```typescript
   * // In Server Component
   * const user = await auth.getUser();
   * if (!user) {
   *   redirect('/login');
   * }
   * ```
   */
  async getUser(): Promise<User | null> {
    this.assertServerEnvironment('getUser');
    const sessionManager = await this.getSessionManager();
    return sessionManager.getUser();
  }

  /**
   * Check if user is authenticated
   *
   * @returns Promise resolving to true if user is authenticated
   *
   * @example
   * ```typescript
   * // In route handler
   * export async function GET() {
   *   if (!(await auth.isAuthenticated())) {
   *     return Response.redirect('/login');
   *   }
   *
   *   return Response.json({ message: 'Protected data' });
   * }
   * ```
   */
  async isAuthenticated(): Promise<boolean> {
    this.assertServerEnvironment('isAuthenticated');
    const sessionManager = await this.getSessionManager();
    return sessionManager.isAuthenticated();
  }

  /**
   * Logout and destroy session
   *
   * Clears the user's session and calls logout callbacks.
   *
   * @example
   * ```typescript
   * // app/logout/route.ts
   * export async function POST() {
   *   await auth.logout();
   *   return Response.redirect('/login');
   * }
   * ```
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
   *
   * Returns a higher-order function that wraps route handlers with authentication context.
   *
   * @param handler - Route handler function to protect
   * @returns Wrapped route handler with authentication context
   *
   * @example
   * ```typescript
   * // app/api/protected/route.ts
   * export const GET = auth.auth(async (request, context) => {
   *   if (!context.isAuthenticated) {
   *     return Response.json({ error: 'Unauthorized' }, { status: 401 });
   *   }
   *
   *   return Response.json({
   *     message: `Hello ${context.user?.name}!`
   *   });
   * });
   * ```
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
   *
   * Generates the Stanford WebAuth login URL for custom redirect handling.
   *
   * @param options - Login options including returnTo URL
   * @returns Promise resolving to the complete login URL
   *
   * @example
   * ```typescript
   * // Custom login handling
   * export async function GET() {
   *   const loginUrl = await auth.getLoginUrl({ returnTo: '/dashboard' });
   *
   *   // Log login attempt
   *   console.log('Redirecting to:', loginUrl);
   *
   *   return Response.redirect(loginUrl);
   * }
   * ```
   */
  async getLoginUrl(options: LoginOptions = {}): Promise<string> {
    return this.samlProvider.getLoginUrl(options);
  }

  /**
   * Refresh session (sliding expiration)
   *
   * Updates session timestamp to extend its lifetime.
   *
   * @returns Promise resolving to refreshed session or null if no session
   *
   * @example
   * ```typescript
   * // In middleware for sliding sessions
   * export async function middleware(request: NextRequest) {
   *   await auth.refreshSession(); // Extend session on each request
   *   return NextResponse.next();
   * }
   * ```
   */
  async refreshSession(): Promise<Session | null> {
    this.assertServerEnvironment('refreshSession');
    const sessionManager = await this.getSessionManager();
    return sessionManager.refreshSession();
  }

  /**
   * Update session with additional metadata
   *
   * Convenience function to add custom data to the session cookie.
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
 *
 * Factory function that creates and configures an AdaptNext instance.
 * This is the recommended way to create an auth instance.
 *
 * @param config - Authentication configuration
 * @returns Configured AdaptNext instance
 *
 * @example
 * ```typescript
 * // lib/auth.ts
 * export const auth = createAdaptNext({
 *   saml: {
 *     issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
 *     idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
 *     returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!
 *   },
 *   session: {
 *     name: 'adapt-auth-session',
 *     secret: process.env.ADAPT_AUTH_SESSION_SECRET!
 *   },
 *   verbose: process.env.NODE_ENV === 'development'
 * });
 * ```
 */
export function createAdaptNext(config: AdaptNextConfig): AdaptNext {
  return new AdaptNext(config);
}

// Export types for convenience
export { type AuthContext, type RouteHandler };

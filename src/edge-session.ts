/**
 * Edge-compatible session management for checking sessions in edge functions
 * This is a lightweight implementation that can decrypt iron-session cookies
 * without requiring Node.js dependencies.
 */

import { Session, User } from './types';
import { unsealData } from 'iron-session';

/**
 * Simple edge-compatible logger for debugging
 */
interface EdgeLogger {
  debug(message: string, meta?: Record<string, unknown>): void;
}

/**
 * Minimal logger that works in edge environments
 */
class EdgeConsoleLogger implements EdgeLogger {
  constructor(private verbose: boolean = false) {}

  debug(message: string, meta?: Record<string, unknown>): void {
    if (this.verbose) {
      console.log(`[DEBUG] ${message}`, meta || {});
    }
  }
}

/**
 * Edge-compatible cookie interface
 */
export interface EdgeCookie {
  name: string;
  value: string;
}

/**
 * Simple cookie parser for edge environments
 */
export class EdgeCookieParser {
  private cookies: Map<string, string> = new Map();

  constructor(cookieHeader?: string | null) {
    if (cookieHeader) {
      this.parseCookies(cookieHeader);
    }
  }

  private parseCookies(cookieHeader: string): void {
    cookieHeader.split(';').forEach(cookie => {
      const [name, ...rest] = cookie.trim().split('=');
      if (name && rest.length > 0) {
        const value = rest.join('='); // Handle values with = in them
        this.cookies.set(name, decodeURIComponent(value));
      }
    });
  }

  get(name: string): string | undefined {
    return this.cookies.get(name);
  }

  getAll(): Record<string, string> {
    return Object.fromEntries(this.cookies);
  }
}

/**
 * Edge-compatible session reader
 * Only supports reading/decrypting sessions - not creating or updating them
 */
export class EdgeSessionReader {
  private readonly secret: string;
  private readonly cookieName: string;
  private readonly logger: EdgeLogger;

  constructor(
    secret: string,
    cookieName: string = 'adapt-auth-session',
    logger?: EdgeLogger
  ) {
    this.secret = secret;
    this.cookieName = cookieName;
    this.logger = logger || new EdgeConsoleLogger();

    if (this.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }
  }

  /**
   * Get session from cookie header string
   */
  async getSessionFromCookieHeader(cookieHeader?: string | null): Promise<Session | null> {
    if (!cookieHeader) {
      return null;
    }

    const parser = new EdgeCookieParser(cookieHeader);
    const cookieValue = parser.get(this.cookieName);

    if (!cookieValue) {
      return null;
    }

    return this.decryptSession(cookieValue);
  }

  /**
   * Get session from Request object
   */
  async getSessionFromRequest(request: Request): Promise<Session | null> {
    const cookieHeader = request.headers.get('cookie');
    return this.getSessionFromCookieHeader(cookieHeader);
  }

  /**
   * Check if session exists and is valid
   */
  async isAuthenticated(request: Request): Promise<boolean> {
    const session = await this.getSessionFromRequest(request);
    return this.isValidSession(session);
  }

  /**
   * Get user from session
   */
  async getUser(request: Request): Promise<User | null> {
    const session = await this.getSessionFromRequest(request);
    return session?.user || null;
  }

  /**
   * Get user ID from session
   */
  async getUserId(request: Request): Promise<string | null> {
    const session = await this.getSessionFromRequest(request);
    return session?.user?.id || null;
  }

  /**
   * Validate session data
   */
  private isValidSession(session: Session | null): boolean {
    if (!session) return false;
    if (!session.user?.id) return false;

    // Check expiration
    if (session.expiresAt && session.expiresAt > 0 && Date.now() > session.expiresAt) {
      this.logger.debug('Session expired', { expiresAt: session.expiresAt });
      return false;
    }

    return true;
  }

  /**
   * Decrypt iron-session cookie value using iron-session's unsealData
   */
  async decryptSession(cookieValue: string): Promise<Session | null> {
    try {
      // Use iron-session's unsealData function directly
      const sessionData = await unsealData<Session>(cookieValue, {
        password: this.secret,
      });

      // Validate session
      if (!this.isValidSession(sessionData)) {
        return null;
      }

      return sessionData;
    } catch (error) {
      this.logger.debug('Failed to decrypt session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      return null;
    }
  }
}

/**
 * Safely get environment variable in edge environments
 */
function getEdgeEnv(key: string): string | undefined {
  try {
    // Try different ways to access environment variables in edge environments
    if (typeof process !== 'undefined' && process.env) {
      return process.env[key];
    }
    // In some edge environments like Deno
    const globalEnv = globalThis as { Deno?: { env: { get: (key: string) => string | undefined } } };
    if (globalEnv.Deno?.env) {
      return globalEnv.Deno.env.get(key);
    }
    // In Cloudflare Workers, env variables are passed to fetch handler
    // This will be undefined here, but that's handled by the caller
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Factory function to create edge session reader with environment variables
 */
export function createEdgeSessionReader(
  secret?: string,
  cookieName?: string,
  logger?: EdgeLogger
): EdgeSessionReader {
  const sessionSecret = secret || getEdgeEnv('ADAPT_AUTH_SESSION_SECRET');
  const sessionName = cookieName || getEdgeEnv('ADAPT_AUTH_SESSION_NAME') || 'adapt-auth-session';

  if (!sessionSecret) {
    throw new Error('Session secret is required. Provide it as parameter or set ADAPT_AUTH_SESSION_SECRET environment variable.');
  }

  return new EdgeSessionReader(sessionSecret, sessionName, logger);
}

/**
 * Convenience function to get user ID from request in edge functions
 */
export async function getUserIdFromRequest(
  request: Request,
  secret?: string,
  cookieName?: string
): Promise<string | null> {
  const reader = createEdgeSessionReader(secret, cookieName);
  return reader.getUserId(request);
}

/**
 * Lightweight user ID extraction that reuses iron-session
 */
export async function getUserIdFromCookie(
  cookieValue: string,
  secret: string
): Promise<string | null> {
  try {
    // Use iron-session for full decryption
    const sessionData = await unsealData<Session>(cookieValue, { password: secret });
    return sessionData?.user?.id || null;
  } catch {
    return null;
  }
}

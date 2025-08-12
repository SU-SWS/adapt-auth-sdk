/**
 * Edge-compatible session management for checking sessions in edge functions
 * This is a lightweight implementation that can decrypt iron-session cookies
 * without requiring Node.js dependencies.
 */

import { Session, User, Logger } from './types';
import { DefaultLogger } from './logger';

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
  private readonly logger: Logger;

  constructor(
    secret: string,
    cookieName: string = 'adapt-auth-session',
    logger?: Logger
  ) {
    this.secret = secret;
    this.cookieName = cookieName;
    this.logger = logger || new DefaultLogger();

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
   * Check if user has specific role/permission
   */
  async hasRole(request: Request, role: string): Promise<boolean> {
    const session = await this.getSessionFromRequest(request);
    if (!session?.meta) return false;

    // Check in various possible role formats
    const roles = session.meta.roles as string[] | undefined;
    const role_list = session.meta.role_list as string[] | undefined;
    const permissions = session.meta.permissions as string[] | undefined;

    return Boolean(
      roles?.includes(role) ||
      role_list?.includes(role) ||
      permissions?.includes(role)
    );
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
   * Decrypt iron-session cookie value
   * This implements a simplified version of iron-session decryption
   * compatible with edge environments
   */
  private async decryptSession(cookieValue: string): Promise<Session | null> {
    try {
      // Iron session format: sealed.signature
      const parts = cookieValue.split('.');
      if (parts.length !== 2) {
        this.logger.debug('Invalid cookie format');
        return null;
      }

      const [sealed, signature] = parts;

      // Verify signature using HMAC
      const isValid = await this.verifySignature(sealed, signature);
      if (!isValid) {
        this.logger.debug('Invalid cookie signature');
        return null;
      }

      // Decrypt the sealed data
      const decrypted = await this.unseal(sealed);
      if (!decrypted) {
        this.logger.debug('Failed to decrypt session data');
        return null;
      }

      // Parse session data
      const sessionData = JSON.parse(decrypted) as Session;

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

  /**
   * Verify cookie signature using HMAC-SHA256
   */
  private async verifySignature(data: string, signature: string): Promise<boolean> {
    try {
      const encoder = new TextEncoder();
      const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(this.secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const signatureBuffer = this.base64UrlToArrayBuffer(signature);
      return await crypto.subtle.verify('HMAC', key, signatureBuffer, encoder.encode(data));
    } catch {
      return false;
    }
  }

  /**
   * Unseal (decrypt) the data using AES-GCM
   * Simplified version compatible with iron-session format
   */
  private async unseal(sealed: string): Promise<string | null> {
    try {
      const sealedData = this.base64UrlToArrayBuffer(sealed);

      // Extract IV (first 12 bytes) and encrypted data (rest)
      const iv = sealedData.slice(0, 12);
      const encrypted = sealedData.slice(12);

      // Derive key from secret
      const key = await this.deriveKey(this.secret);

      // Decrypt using AES-GCM
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        encrypted
      );

      return new TextDecoder().decode(decrypted);
    } catch {
      return null;
    }
  }

  /**
   * Derive encryption key from secret
   */
  private async deriveKey(secret: string): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('iron-session-salt'), // Iron session uses a fixed salt
        iterations: 1000,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  /**
   * Convert Base64 URL to ArrayBuffer
   */
  private base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
    // Add padding if needed
    const padded = base64Url + '==='.slice(0, (4 - base64Url.length % 4) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

    // Use native atob for edge function compatibility
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}

/**
 * Factory function to create edge session reader with environment variables
 */
export function createEdgeSessionReader(
  secret?: string,
  cookieName?: string,
  logger?: Logger
): EdgeSessionReader {
  const sessionSecret = secret ||
    (typeof process !== 'undefined' ? process.env?.ADAPT_AUTH_SESSION_SECRET : undefined);

  const sessionName = cookieName ||
    (typeof process !== 'undefined' ? process.env?.ADAPT_AUTH_SESSION_NAME : undefined) ||
    'adapt-auth-session';

  if (!sessionSecret) {
    throw new Error('Session secret is required. Provide it as parameter or set ADAPT_AUTH_SESSION_SECRET environment variable.');
  }

  return new EdgeSessionReader(sessionSecret, sessionName, logger);
}

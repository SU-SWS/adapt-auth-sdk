import { RelayStatePayload } from './types';

/**
 * Utility functions for authentication
 */
export class AuthUtils {
  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  /**
   * Generate a cryptographically secure random string
   */
  static generateNonce(length = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Create HMAC-SHA256 signature
   */
  static async createHMAC(data: string, secret: string): Promise<string> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, this.encoder.encode(data));
    return this.arrayBufferToBase64Url(signature);
  }

  /**
   * Verify HMAC-SHA256 signature
   */
  static async verifyHMAC(data: string, signature: string, secret: string): Promise<boolean> {
    const key = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = this.base64UrlToArrayBuffer(signature);
    return await crypto.subtle.verify('HMAC', key, signatureBuffer, this.encoder.encode(data));
  }

  /**
   * Create signed RelayState
   */
  static async createRelayState(
    payload: RelayStatePayload,
    secret: string
  ): Promise<string> {
    const data = this.base64UrlEncode(JSON.stringify(payload));
    const signature = await this.createHMAC(data, secret);
    return `${data}.${signature}`;
  }

  /**
   * Verify and parse RelayState
   */
  static async verifyRelayState(
    relayState: string,
    secret: string,
    maxAgeSec = 300 // 5 minutes default
  ): Promise<RelayStatePayload | null> {
    try {
      const [data, signature] = relayState.split('.');
      if (!data || !signature) {
        return null;
      }

      // Verify signature
      const isValid = await this.verifyHMAC(data, signature, secret);
      if (!isValid) {
        return null;
      }

      // Parse payload
      const payload: RelayStatePayload = JSON.parse(this.base64UrlDecode(data));

      // Check age
      const now = Math.floor(Date.now() / 1000);
      if (now - payload.issuedAt > maxAgeSec) {
        return null;
      }

      return payload;
    } catch {
      return null;
    }
  }

  /**
   * Sanitize and validate returnTo URL
   */
  static sanitizeReturnTo(returnTo: string, allowedOrigins: string[]): string | null {
    try {
      const url = new URL(returnTo);

      // Only allow same-origin URLs or explicitly allowed origins
      const isAllowed = allowedOrigins.some(origin => {
        const allowedUrl = new URL(origin);
        return url.origin === allowedUrl.origin;
      });

      if (!isAllowed) {
        return null;
      }

      // Prevent javascript: protocol and other dangerous schemes
      if (!['http:', 'https:'].includes(url.protocol)) {
        return null;
      }

      return url.toString();
    } catch {
      return null;
    }
  }

  /**
   * Check cookie size and warn if too large
   */
  static checkCookieSize(
    cookieValue: string,
    threshold = 3500,
    logger?: { warn: (msg: string, meta?: Record<string, unknown>) => void }
  ): void {
    const size = new Blob([cookieValue]).size;

    if (size > threshold && logger) {
      logger.warn('Cookie size exceeds threshold', {
        size,
        threshold,
        warning: 'Large cookies may cause issues with some browsers and proxies'
      });
    }
  }

  /**
   * Base64 URL encode
   */
  static base64UrlEncode(data: string): string {
    // Use native btoa with proper Unicode handling for edge function compatibility
    const base64 = btoa(unescape(encodeURIComponent(data)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Base64 URL decode
   */
  static base64UrlDecode(encoded: string): string {
    // Add padding if needed
    const padded = encoded + '==='.slice(0, (4 - encoded.length % 4) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');

    // Use native atob with proper Unicode handling for edge function compatibility
    return decodeURIComponent(escape(atob(base64)));
  }

  /**
   * Convert ArrayBuffer to Base64 URL
   */
  private static arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const binary = Array.from(bytes, byte => String.fromCharCode(byte)).join('');

    // Use native btoa for edge function compatibility
    const base64 = btoa(binary);

    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Convert Base64 URL to ArrayBuffer
   */
  private static base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
    const binary = this.base64UrlDecode(base64Url);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Generate CSRF token
   */
  static generateCSRFToken(): string {
    return this.generateNonce(32);
  }

  /**
   * Validate CSRF token
   */
  static validateCSRFToken(token: string, expectedToken: string): boolean {
    if (!token || !expectedToken || token.length !== expectedToken.length) {
      return false;
    }

    // Constant-time comparison to prevent timing attacks
    let result = 0;
    for (let i = 0; i < token.length; i++) {
      result |= token.charCodeAt(i) ^ expectedToken.charCodeAt(i);
    }
    return result === 0;
  }
}

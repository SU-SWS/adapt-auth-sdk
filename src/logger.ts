import { Logger } from './types';

/**
 * Default logger implementation with structured logging and redaction
 */
export class DefaultLogger implements Logger {
  private verbose: boolean;
  private requestId?: string;
  private userId?: string;

  constructor(verbose = false) {
    this.verbose = verbose;
  }

  setContext(requestId?: string, userId?: string) {
    this.requestId = requestId;
    this.userId = userId;
  }

  private log(level: string, message: string, meta: Record<string, unknown> = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      requestId: this.requestId,
      userId: this.userId,
      ...this.redactSecrets(meta),
    };

    // Only log debug messages in verbose mode
    if (level === 'debug' && !this.verbose) {
      return;
    }

    console.log(JSON.stringify(logEntry));
  }

  private redactSecrets(obj: Record<string, unknown>): Record<string, unknown> {
    const redacted = { ...obj };
    const secretKeys = [
      'password',
      'secret',
      'token',
      'cert',
      'certificate',
      'samlresponse',
      'cookie',
      'authorization',
      'private',
      'pvk',
    ];

    for (const [key, value] of Object.entries(redacted)) {
      const lowerKey = key.toLowerCase();

      // Only redact if the key name specifically indicates sensitive data
      const shouldRedact = secretKeys.some(secret => lowerKey.includes(secret));

      if (shouldRedact) {
        if (typeof value === 'string' && value.length > 0) {
          // For certificates, show fingerprint/hash instead
          if (lowerKey.includes('cert')) {
            redacted[key] = `[CERT_HASH:${this.hashString(value)}]`;
          } else {
            redacted[key] = '[REDACTED]';
          }
        } else {
          redacted[key] = '[REDACTED]';
        }
      } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        // Recursively redact nested objects
        redacted[key] = this.redactSecrets(value as Record<string, unknown>);
      }
    }

    return redacted;
  }

  private hashString(input: string): string {
    // Simple hash for fingerprinting (not cryptographically secure)
    let hash = 0;
    for (let i = 0; i < Math.min(input.length, 100); i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32-bit integer
    }
    return Math.abs(hash).toString(16);
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.log('debug', message, meta);
  }

  info(message: string, meta?: Record<string, unknown>): void {
    this.log('info', message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.log('warn', message, meta);
  }

  error(message: string, meta?: Record<string, unknown>): void {
    this.log('error', message, meta);
  }
}

/**
 * Console logger for simple environments
 */
export class ConsoleLogger implements Logger {
  debug(message: string, meta?: Record<string, unknown>): void {
    console.debug('[DEBUG]', message, meta);
  }

  info(message: string, meta?: Record<string, unknown>): void {
    console.info('[INFO]', message, meta);
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    console.warn('[WARN]', message, meta);
  }

  error(message: string, meta?: Record<string, unknown>): void {
    console.error('[ERROR]', message, meta);
  }
}

/**
 * Silent logger for testing or minimal environments
 */
export class SilentLogger implements Logger {
  debug(): void {
    // Silent
  }

  info(): void {
    // Silent
  }

  warn(): void {
    // Silent
  }

  error(): void {
    // Silent
  }
}

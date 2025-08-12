// Enhanced error handling classes for better debugging and user experience
import { AuthError } from './types';

/**
 * SAML-specific error for authentication failures
 */
export class SAMLError extends AuthError {
  constructor(
    message: string,
    public readonly samlCode: string,
    public readonly issuer?: string,
    statusCode = 400
  ) {
    super(message, `SAML_${samlCode}`, statusCode);
    this.name = 'SAMLError';
  }
}

/**
 * Session-specific error for session management failures
 */
export class SessionError extends AuthError {
  constructor(
    message: string,
    public readonly sessionCode: string,
    public readonly sessionName?: string,
    statusCode = 500
  ) {
    super(message, `SESSION_${sessionCode}`, statusCode);
    this.name = 'SessionError';
  }
}

/**
 * Configuration error for invalid setup
 */
export class ConfigError extends AuthError {
  constructor(
    message: string,
    public readonly configField: string,
    statusCode = 500
  ) {
    super(message, `CONFIG_${configField.toUpperCase()}_INVALID`, statusCode);
    this.name = 'ConfigError';
  }
}

/**
 * Network/timeout error for external service calls
 */
export class NetworkError extends AuthError {
  constructor(
    message: string,
    public readonly operation: string,
    public readonly originalError?: Error,
    statusCode = 503
  ) {
    super(message, `NETWORK_${operation.toUpperCase()}_FAILED`, statusCode);
    this.name = 'NetworkError';
  }
}

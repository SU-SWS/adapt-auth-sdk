/**
 * ADAPT Auth SDK - Framework-agnostic SAML authentication for Oracle IDCS
 *
 * A comprehensive TypeScript library for SAML 2.0 authentication with Oracle IDCS.
 * Designed for serverless environments with cookie-only sessions using iron-session.
 *
 * @packageDocumentation
 * @version 2.0.0
 * @author Stanford University Web Services
 * @license MIT
 *
 * @example
 * ```typescript
 * // Next.js App Router usage
 * import { createAdaptNext } from '@stanford-uat/adapt-auth-sdk';
 *
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
 *
 * @example
 * ```typescript
 * // Framework-agnostic usage with core classes
 * import { SAMLProvider, SessionManager, createWebCookieStore } from '@stanford-uat/adapt-auth-sdk';
 *
 * const samlProvider = new SAMLProvider({ ... });
 * const sessionManager = new SessionManager(createWebCookieStore(req, res), { ... });
 * ```
 */

// Export all type definitions
export * from './types';

// Export core authentication classes
export * from './saml';
export * from './session';
export * from './edge-session';
export * from './logger';
export * from './utils';

/**
 * Next.js-specific integration classes and utilities
 * Import specific exports to avoid name conflicts
 */
export { AdaptNext, createAdaptNext } from './next';

/**
 * Re-export commonly used classes and functions for convenience
 * These are the primary building blocks for most authentication implementations
 */

/** SAML authentication provider for Stanford WebAuth */
export { SAMLProvider, createSAMLProvider } from './saml';

/** Session management with cookie-based storage */
export { SessionManager, createExpressCookieStore, createWebCookieStore } from './session';

/** Edge-compatible session reading for Netlify/Vercel functions */
export { EdgeSessionReader, EdgeCookieParser, createEdgeSessionReader, getUserIdFromRequest, getUserIdFromCookie } from './edge-session';

/** Structured logging implementations with security redaction */
export { DefaultLogger, ConsoleLogger, SilentLogger } from './logger';

/** Authentication utility functions and helpers */
export { AuthUtils } from './utils';
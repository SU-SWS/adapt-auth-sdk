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
 *     callbackOrigin: process.env.ADAPT_AUTH_SAML_CALLBACK_ORIGIN!
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
export * from './types.js';

// Export core authentication classes
export * from './saml.js';
export * from './session.js';
export * from './edge-session.js';
export * from './logger.js';
export * from './utils.js';

/**
 * Next.js-specific integration classes and utilities
 *
 * NOTE: Next.js integration is now available as a separate import:
 * import { AdaptNext, createAdaptNext } from 'adapt-auth-sdk/next'
 *
 * This prevents the core package from depending on Next.js and avoids
 * bundling issues in non-Next.js environments.
 */
// export { AdaptNext, createAdaptNext } from './next.js'; // Removed from default exports

/**
 * Re-export commonly used classes and functions for convenience
 * These are the primary building blocks for most authentication implementations
 */

/** SAML authentication provider for Oracle IDCS SAML */
export { SAMLProvider, createSAMLProvider } from './saml.js';

/** Session management with cookie-based storage */
export { SessionManager, createExpressCookieStore, createWebCookieStore } from './session.js';

/** Edge-compatible session reading for Netlify/Vercel functions */
export { EdgeSessionReader, EdgeCookieParser, createEdgeSessionReader, getUserIdFromRequest, getUserIdFromCookie } from './edge-session.js';

/** Structured logging implementations with security redaction */
export { DefaultLogger, ConsoleLogger, SilentLogger } from './logger.js';

/** Authentication utility functions and helpers */
export { AuthUtils } from './utils.js';
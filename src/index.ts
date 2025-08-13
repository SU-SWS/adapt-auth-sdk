// Main exports
export * from './types';
export * from './saml';
export * from './session';
export * from './edge-session';
export * from './logger';
export * from './utils';
export * from './next';

// Re-export commonly used classes and functions
export { SAMLProvider, createSAMLProvider } from './saml';
export { SessionManager, createExpressCookieStore, createWebCookieStore } from './session';
export { EdgeSessionReader, EdgeCookieParser, createEdgeSessionReader, getUserIdFromRequest } from './edge-session';
export { DefaultLogger, ConsoleLogger, SilentLogger } from './logger';
export { AuthUtils } from './utils';
export { AdaptNext, createAdaptNext } from './next';
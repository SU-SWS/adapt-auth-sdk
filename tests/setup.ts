// Jest setup file
// This file runs before each test file
import { webcrypto } from 'crypto';

// Set default test environment variables
Object.assign(process.env, {
  NODE_ENV: 'test',
  ADAPT_AUTH_SAML_ENTITY: 'test-entity',
  ADAPT_AUTH_SAML_CERT: 'test-cert',
  ADAPT_AUTH_SAML_DECRYPTION_KEY: 'test-decryption-key',
  ADAPT_AUTH_SAML_RETURN_ORIGIN: 'http://localhost:3000',
  ADAPT_AUTH_SESSION_SECRET: 'test-session-secret-that-is-at-least-32-characters-long',
  ADAPT_AUTH_SESSION_NAME: 'test-session',
});

// Mock Web Crypto API for Node.js environments that don't have it
if (!globalThis.crypto) {
  globalThis.crypto = webcrypto as Crypto;
}

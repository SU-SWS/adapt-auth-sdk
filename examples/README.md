# ADAPT Auth SDK Examples

This directory contains comprehensive examples showing how to integrate ADAPT Auth SDK with different frameworks and environments.

## Available Examples

### 🌐 Edge Functions
**File:** [`edge-functions.md`](./edge-functions.md)

**Use Case:** Ultra-fast session validation in edge computing environments

**Platforms:**
- Vercel Edge Functions
- Netlify Edge Functions
- Cloudflare Workers
- Deno Deploy

**Key Features:**
- Read-only session validation
- Zero Node.js dependencies
- Sub-50ms response times
- Works with Web APIs only

---

### ⚡ Next.js App Router
**File:** [`nextjs-app-router.md`](./nextjs-app-router.md)

**Use Case:** Full-stack React applications with server-side rendering

**Key Features:**
- Built-in Next.js adapter (`createAdaptNext`)
- Server Components integration
- Client Components with hooks
- Middleware protection
- API routes
- Role-based access control

**Best For:** Modern React applications, server-side rendering, hybrid edge/server architecture

---

### 🚀 Express.js
**File:** [`express.md`](./express.md)

**Use Case:** Traditional Node.js web applications and APIs

**Key Features:**
- Middleware-based authentication
- Template engine integration (EJS)
- Role-based access control
- Database integration examples
- Session refresh middleware
- Comprehensive error handling

**Best For:** Traditional web applications, REST APIs, microservices

---

### ⚡ Fastify
**File:** [`fastify.md`](./fastify.md)

**Use Case:** High-performance Node.js applications

**Key Features:**
- Plugin-based architecture
- Hook system integration
- Rate limiting for auth routes
- Schema validation
- Route organization
- Performance optimized

**Best For:** High-throughput APIs, performance-critical applications, microservices

---

### 🌐 Web Standards (Universal)
**File:** [`web-standards.md`](./web-standards.md)

**Use Case:** Runtime-agnostic applications using modern Web APIs

**Platforms:**
- Node.js 18+
- Bun
- Deno
- Any Web Standards compatible runtime

**Key Features:**
- Uses only Web Standards (Request, Response, URL, etc.)
- Runtime detection and adaptation
- Zero framework dependencies
- Docker deployment examples

**Best For:** Cross-platform deployment, modern runtimes, serverless functions

---

## Quick Comparison

| Example | Performance | Complexity | Use Case | Runtime |
|---------|-------------|------------|----------|---------|
| **Edge Functions** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Session validation only | Edge |
| **Next.js** | ⭐⭐⭐⭐ | ⭐⭐⭐ | Full-stack React apps | Node.js |
| **Express** | ⭐⭐⭐ | ⭐⭐⭐ | Traditional web apps | Node.js |
| **Fastify** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | High-performance APIs | Node.js |
| **Web Standards** | ⭐⭐⭐⭐ | ⭐⭐ | Universal deployment | Any |

## Common Configuration

All examples use the same basic configuration pattern:

```typescript
// Required environment variables
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate-string
ADAPT_AUTH_SAML_RETURN_ORIGIN=https://your-app.com
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key

// Optional environment variables
ADAPT_AUTH_RELAY_STATE_SECRET=another-32-character-secret-key
```

```typescript
// Basic SDK configuration (all examples)
import { createAdaptNext } from 'adapt-auth-sdk'; // or core components

const auth = createAdaptNext({
  saml: {
    // Required
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,

    // Optional - sensible defaults provided
    relayStateSecret: process.env.ADAPT_AUTH_RELAY_STATE_SECRET,
  },
  session: {
    // Required
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,

    // Optional - secure defaults provided
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7, // 1 week
    },
  },
});
```

## Architecture Patterns

### 🏗️ Hybrid Edge + Server (Recommended)

Use edge functions for fast session validation and Node.js servers for full SAML processing:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│    Edge     │────│  Node.js    │
│             │    │  Function   │    │   Server    │
│             │    │             │    │             │
│ UI + Forms  │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │             │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Implementation:**
- Edge: Use [`edge-functions.md`](./edge-functions.md) for session checking
- Server: Use [`nextjs-app-router.md`](./nextjs-app-router.md) or [`express.md`](./express.md) for authentication

### 🖥️ Server-Side Only (Traditional)

Full authentication and session management on the server:

```
┌─────────────┐    ┌─────────────┐
│   Browser   │────│  Node.js    │
│             │    │   Server    │
│             │    │             │
│ UI + Forms  │    │ SAML +      │
│             │    │ Sessions +  │
│             │    │ Validation  │
└─────────────┘    └─────────────┘
```

**Implementation:**
- Use [`express.md`](./express.md), [`fastify.md`](./fastify.md), or [`web-standards.md`](./web-standards.md)

### ☁️ Serverless Functions

Authentication spread across multiple serverless functions:

```
┌─────────────┐    ┌─────────────┐
│   Browser   │────│ Serverless  │
│             │    │ Functions   │
│             │    │             │
│ UI + Forms  │    │ /auth/login │
│             │    │ /auth/acs   │
│             │    │ /api/*      │
└─────────────┘    └─────────────┘
```

**Implementation:**
- Use [`web-standards.md`](./web-standards.md) for individual functions
- Use [`nextjs-app-router.md`](./nextjs-app-router.md) for Vercel deployment

## Getting Started

1. **Choose your platform** from the examples above
2. **Set up environment variables** (see common configuration)
3. **Follow the specific example** for your chosen platform
4. **Test authentication flow**:
   - Visit `/auth/login`
   - Complete Stanford SAML authentication
   - Access protected routes
   - Test logout functionality

## Security Best Practices

All examples implement these security measures:

- ✅ **HttpOnly cookies** prevent XSS attacks
- ✅ **Secure cookies** in production (HTTPS only)
- ✅ **SameSite protection** prevents CSRF
- ✅ **HMAC-signed RelayState** prevents tampering
- ✅ **Session expiration** with configurable TTL
- ✅ **Clock skew tolerance** for SAML validation
- ✅ **CSRF token validation** for state changes
- ✅ **Input sanitization** for returnTo URLs

## Troubleshooting

### Common Issues

1. **"Authentication failed"**
   - Check SAML certificate format
   - Verify entity ID matches IdP configuration
   - Ensure callback URL is registered

2. **"Session invalid"**
   - Verify session secret is 32+ characters
   - Check cookie domain/path configuration
   - Ensure same secret used for encryption/decryption

3. **"CSRF token mismatch"**
   - Include CSRF token in forms
   - Check SameSite cookie settings
   - Verify origin headers

### Debug Mode

Enable verbose logging in any example:

```typescript
const auth = createAdaptNext({
  // ... other config
  verbose: true, // Enable debug logging
  logger: customLogger, // Optional custom logger
});
```

### Testing

Each example includes testing strategies:
- Unit tests for authentication logic
- Integration tests for full auth flow
- Mock configurations for development

For more detailed information, explore the individual example files linked above.

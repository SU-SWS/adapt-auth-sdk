# ADAPT Auth SDK Examples

This directory contains comprehensive examples showing how to integrate ADAPT Auth SDK with Next.js and Gatsby frameworks for localhost development and Netlify production deployment.

## Available Examples

### ⚡ Next.js App Router
**File:** [`nextjs-app-router.md`](./nextjs-app-router.md)

**Use Case:** Full-stack React applications with server-side rendering

**Environments:**
- Localhost development
- Netlify production deployment

**Key Features:**
- Built-in Next.js adapter (`createAdaptNext`)
- Server Components integration
- Client Components with hooks
- Middleware protection
- API routes
- Role-based access control

**Best For:** Modern React applications, server-side rendering, hybrid edge/server architecture

---

### 🚀 Gatsby
**File:** [`gatsby.md`](./gatsby.md)

**Use Case:** Static site generation with dynamic authentication

**Environments:**
- Localhost development
- Netlify production deployment

**Key Features:**
- Gatsby Functions for API endpoints
- Client-side authentication guards
- Static site optimization
- Progressive enhancement
- Role-based access control
- Netlify edge function integration

**Best For:** Static sites, blogs, marketing sites with protected content

---

### 🌐 Netlify Edge Functions
**File:** [`edge-functions.md`](./edge-functions.md)

**Use Case:** Ultra-fast session validation at the edge

**Environments:**
- Localhost development with Netlify CLI
- Netlify production edge deployment

**Key Features:**
- Read-only session validation
- Zero Node.js dependencies
- Sub-50ms response times
- Works with Web APIs only

**Best For:** Performance-critical session checks, protecting static content

---

## Quick Comparison

| Example | Performance | Complexity | Use Case | Deployment |
|---------|-------------|------------|----------|------------|
| **Next.js** | ⭐⭐⭐⭐ | ⭐⭐⭐ | Full-stack React apps | Netlify |
| **Gatsby** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Static sites + auth | Netlify |
| **Edge Functions** | ⭐⭐⭐⭐⭐ | ⭐⭐ | Session validation only | Netlify |

## Common Configuration

All examples use the same basic configuration pattern optimized for localhost development and Netlify production:

```bash
# Required environment variables
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate-string
ADAPT_AUTH_SAML_RETURN_ORIGIN=http://localhost:3000  # or https://yoursite.netlify.app
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key

# Optional environment variables
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
      // Session-only cookies (no maxAge)
    },
  },
});
```

## Deployment Architecture

### 🏗️ Localhost + Netlify (Recommended)

Optimized for local development and Netlify production deployment:

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│  Localhost  │────│   Netlify   │
│             │    │     Dev     │    │ Production  │
│             │    │             │    │             │
│ UI + Forms  │    │ Next.js/    │    │ Functions + │
│             │    │ Gatsby      │    │ Edge        │
│             │    │             │    │ Functions   │
└─────────────┘    └─────────────┘    └─────────────┘
```

**Implementation:**
- Development: Use framework dev servers (Next.js: `npm run dev`, Gatsby: `gatsby develop`)
- Production: Deploy to Netlify with automatic CI/CD
- Edge: Optional Netlify edge functions for performance optimization

## Getting Started

1. **Choose your framework** from the examples above
2. **Set up environment variables** (see common configuration)
3. **Follow the specific example** for your chosen framework
4. **Test authentication flow**:
   - Visit `/auth/login` or click login button
   - Complete Stanford SAML authentication
   - Access protected routes
   - Test logout functionality

### Local Development

```bash
# Next.js
npm run dev          # http://localhost:3000

# Gatsby
gatsby develop       # http://localhost:8000

# Netlify CLI (for edge functions)
netlify dev          # http://localhost:8888
```

### Production Deployment

```bash
# Deploy to Netlify
netlify deploy --prod

# Or connect GitHub repository for automatic deployments
```

## Security Best Practices

All examples implement these security measures optimized for localhost and Netlify:

- ✅ **HttpOnly cookies** prevent XSS attacks
- ✅ **Secure cookies** in production (HTTPS only on Netlify)
- ✅ **SameSite protection** prevents CSRF
- ✅ **URL sanitization** prevents open redirects
- ✅ **Session-only cookies** expire when browser closes
- ✅ **Clock skew tolerance** for SAML validation
- ✅ **CSRF token validation** for state changes
- ✅ **Input sanitization** for returnTo URLs

### Environment-Specific Security

**Localhost Development:**
- HTTP allowed for local development
- Relaxed cookie security for testing
- Detailed error logging enabled

**Netlify Production:**
- HTTPS required (automatic with Netlify)
- Full cookie security enabled
- Error logging minimized for security

## Troubleshooting

### Common Issues

1. **"Authentication failed"**
   - Check SAML certificate format
   - Verify entity ID matches IdP configuration
   - Ensure callback URL is registered with Stanford WebAuth

2. **"Session invalid"**
   - Verify session secret is 32+ characters
   - Check cookie domain/path configuration
   - Ensure same secret used for encryption/decryption

3. **"CSRF token mismatch"**
   - Include CSRF token in forms
   - Check SameSite cookie settings
   - Verify origin headers

### Localhost vs Netlify Issues

4. **"Works locally but not on Netlify"**
   - Update `ADAPT_AUTH_SAML_RETURN_ORIGIN` to Netlify URL
   - Check environment variables in Netlify dashboard
   - Verify secure cookie settings for production

5. **"Netlify Functions not found"**
   - Check `netlify.toml` configuration
   - Ensure functions are in correct directory
   - Verify redirects for API routes

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
- Netlify preview deployments for staging

For more detailed information, explore the individual example files linked above.

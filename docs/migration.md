# Migration Guide

This guide helps you migrate from ADAPT Auth SDK v1.x to v2.0.

## Overview of Changes

ADAPT Auth SDK v2.0 introduces significant architectural improvements:

- **Framework Agnostic**: Works with any framework (Next.js, Express, etc.)
- **Cookie-Only Sessions**: No server-side session storage required
- **Enhanced Security**: Built-in CSRF protection and URL sanitization
- **Modern TypeScript**: Full TypeScript rewrite with strict typing
- **Simplified API**: Cleaner, more intuitive interfaces

## Breaking Changes

### 1. Package Installation

```bash
# Remove v1.x
npm uninstall adapt-auth-sdk@1.x

# Install v2.0
npm install adapt-auth-sdk@^2.0
```

### 2. Import Changes

```typescript
// v1.x
import { AdaptAuth } from 'adapt-auth-sdk';

// v2.0
import { createAdaptNext } from 'adapt-auth-sdk';
// or for other frameworks
import { SAMLProvider, SessionManager } from 'adapt-auth-sdk';
```

### 3. Configuration Structure

```typescript
// v1.x
const auth = new AdaptAuth({
  entityId: 'your-entity',
  certificate: 'cert-data',
  sessionSecret: 'secret',
});

// v2.0
const auth = createAdaptNext({
  saml: {
    issuer: 'your-entity',
    idpCert: 'cert-data',
    returnToOrigin: 'https://your-app.com',
  },
  session: {
    name: 'adapt-auth-session',
    secret: 'secret',
  },
});
```

### 4. Environment Variables

Update your environment variable names:

This section provides a detailed mapping of environment variables from v1.x to v2.0, including which variables are still used, renamed, or no longer needed.

### Required Variables (Must Be Set)

| v1.x Variable | v2.0 Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `ADAPT_AUTH_SAML_ENTITY` | `ADAPT_AUTH_SAML_ENTITY` | ✅ **Same** | SAML entity ID (required) |
| `ADAPT_AUTH_SAML_CERT` | `ADAPT_AUTH_SAML_CERT` | ✅ **Same** | IdP certificate (required) |
| `ADAPT_AUTH_SESSION_SECRET` | `ADAPT_AUTH_SESSION_SECRET` | ✅ **Same** | Session encryption secret (required) |
| `ADAPT_AUTH_SAML_RETURN_ORIGIN` | `ADAPT_AUTH_SAML_RETURN_ORIGIN` | ✅ **Same** | Application base URL (required) |

### Optional Variables (Still Supported)

| v1.x Variable | v2.0 Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `ADAPT_AUTH_SAML_SP_URL` | `ADAPT_AUTH_SAML_SP_URL` | ✅ **Same** | Service Provider login URL |
| `ADAPT_AUTH_SAML_RETURN_PATH` | `ADAPT_AUTH_SAML_RETURN_PATH` | ✅ **Same** | ACS path component |
| `ADAPT_AUTH_SAML_DECRYPTION_KEY` | `ADAPT_AUTH_SAML_DECRYPTION_KEY` | ✅ **Same** | Private key for decryption |
| `ADAPT_AUTH_SESSION_NAME` | `ADAPT_AUTH_SESSION_NAME` | ✅ **Same** | Session cookie name |

### Deprecated Variables (No Longer Used)

| v1.x Variable | v2.0 Equivalent | Status | Migration Notes |
|---------------|-----------------|--------|-----------------|
| `ADAPT_AUTH_SAML_RETURN_URL` | *Not used* | ❌ **Removed** | Use `ADAPT_AUTH_SAML_RETURN_ORIGIN` + `ADAPT_AUTH_SAML_RETURN_PATH` |
| `ADAPT_AUTH_SESSION_EXPIRES_IN` | *Not configurable* | ❌ **Removed** | Sessions now expire when browser closes |
| `ADAPT_AUTH_SESSION_LOGOUT_URL` | *Application logic* | ❌ **Removed** | Handle logout redirects in your app |
| `ADAPT_AUTH_SESSION_UNAUTHORIZED_URL` | *Application logic* | ❌ **Removed** | Handle unauthorized redirects in your app |

### 5. API Methods

All methods are now asynchronous:

```typescript
// v1.x
auth.login(req, res);
auth.callback(req, res);
const user = auth.getUser(req);

// v2.0
await auth.login(request);
await auth.authenticate(request);
const session = await auth.getSession(request);
const user = session?.user;
```




### Handling Removed Functionality

**Session Expiration (`ADAPT_AUTH_SESSION_EXPIRES_IN`)**
```typescript
// v1.x: Configurable session expiration
ADAPT_AUTH_SESSION_EXPIRES_IN="24h"

// v2.0: Sessions expire when browser closes
// No configuration needed - this is now the default behavior
```

**Logout URL (`ADAPT_AUTH_SESSION_LOGOUT_URL`)**
```typescript
// v1.x: Automatic redirect after logout
ADAPT_AUTH_SESSION_LOGOUT_URL="/login"

// v2.0: Handle in your logout route
export async function POST(request: Request) {
  await auth.logout(request);
  return Response.redirect('/login'); // Handle redirect in your code
}
```

**Unauthorized URL (`ADAPT_AUTH_SESSION_UNAUTHORIZED_URL`)**
```typescript
// v1.x: Automatic redirect for unauthorized requests
ADAPT_AUTH_SESSION_UNAUTHORIZED_URL="/unauthorized"

// v2.0: Handle in middleware or route handlers
export async function GET(request: Request) {
  const session = await auth.getSession(request);
  if (!session) {
    return Response.redirect('/unauthorized'); // Handle in your code
  }
  // ... continue with protected logic
}
```
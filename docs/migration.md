# Migration Guide

This guide helps you migrate between ADAPT Auth SDK versions.

---

## v2.0 → v2.1 Migration

Version 2.1 introduces clearer naming conventions to distinguish between the **callback URL** (where the IdP posts SAML responses) and the **final destination** (where users are redirected after authentication).

### Summary of Changes

| What Changed | Old Name | New Name |
|--------------|----------|----------|
| Config: IdP callback origin | `returnToOrigin` | `callbackOrigin` |
| Config: IdP callback path | `returnToPath` | `callbackPath` |
| Login option | `returnTo` | `finalDestination` |
| Authenticate result | `returnTo` | `finalDestination` |
| Environment variable | `ADAPT_AUTH_SAML_RETURN_ORIGIN` | `ADAPT_AUTH_SAML_CALLBACK_ORIGIN` |
| Environment variable | `ADAPT_AUTH_SAML_RETURN_PATH` | `ADAPT_AUTH_SAML_CALLBACK_PATH` |
| RelayState payload key | `return_to` | `return_to` *(unchanged)* |

### Why the Change?

The previous naming was confusing because `returnTo` was used for two different concepts:
- **Callback URL**: Where the Identity Provider posts SAML responses back to your app
- **Final Destination**: Where users should be redirected after successful authentication

The new naming makes it clear:
- `callbackOrigin` / `callbackPath` → The URL the IdP posts back to (ACS endpoint)
- `finalDestination` → Where users go after authentication completes

### Configuration Changes

```diff
// lib/auth.ts
export const auth = createAdaptNext({
  saml: {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
-   returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
-   returnToPath: '/api/auth/acs',
+   callbackOrigin: process.env.ADAPT_AUTH_SAML_CALLBACK_ORIGIN!,
+   callbackPath: '/api/auth/acs',
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  },
});
```

### Environment Variable Changes

```diff
# .env.local
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate
- ADAPT_AUTH_SAML_RETURN_ORIGIN=https://your-app.com
- ADAPT_AUTH_SAML_RETURN_PATH=/api/auth/acs
+ ADAPT_AUTH_SAML_CALLBACK_ORIGIN=https://your-app.com
+ ADAPT_AUTH_SAML_CALLBACK_PATH=/api/auth/acs
ADAPT_AUTH_SESSION_SECRET=your-secret
```

### Login Route Changes

```diff
// app/api/auth/login/route.ts
export async function GET(request: Request) {
  const url = new URL(request.url);
- const returnTo = url.searchParams.get('returnTo') || '/';
- return auth.login({ returnTo });
+ const destination = url.searchParams.get('returnTo') || '/';
+ return auth.login({ finalDestination: destination });
}
```

### ACS (Callback) Route Changes

```diff
// app/api/auth/acs/route.ts
export async function POST(request: Request) {
- const { user, session, returnTo } = await auth.authenticate(request);
- return Response.redirect(returnTo || '/dashboard');
+ const { user, session, finalDestination } = await auth.authenticate(request);
+ return Response.redirect(finalDestination || '/dashboard');
}
```

### Framework-Agnostic Usage Changes

```diff
// Using SAMLProvider directly
const samlProvider = new SAMLProvider({
  issuer: 'your-entity',
  idpCert: 'cert-data',
- returnToOrigin: 'https://your-app.com',
- returnToPath: '/auth/callback',
+ callbackOrigin: 'https://your-app.com',
+ callbackPath: '/auth/callback',
});

// Login
- const url = await samlProvider.getLoginUrl({ returnTo: '/dashboard' });
+ const url = await samlProvider.getLoginUrl({ finalDestination: '/dashboard' });

// Authenticate
- const { user, returnTo } = await samlProvider.authenticate({ req: request });
+ const { user, finalDestination } = await samlProvider.authenticate({ req: request });
```

### Quick Migration Checklist

- [ ] Update `returnToOrigin` → `callbackOrigin` in configuration
- [ ] Update `returnToPath` → `callbackPath` in configuration (if used)
- [ ] Update `ADAPT_AUTH_SAML_RETURN_ORIGIN` → `ADAPT_AUTH_SAML_CALLBACK_ORIGIN` in environment
- [ ] Update `ADAPT_AUTH_SAML_RETURN_PATH` → `ADAPT_AUTH_SAML_CALLBACK_PATH` in environment (if used)
- [ ] Update `returnTo` → `finalDestination` in `login()` options
- [ ] Update `returnTo` → `finalDestination` in `authenticate()` result destructuring
- [ ] Search codebase for any remaining `returnTo` references in auth-related code

### TypeScript Type Changes

If you're using TypeScript, the type definitions have been updated:

```typescript
// LoginOptions
interface LoginOptions {
  finalDestination?: string;  // was: returnTo
  [key: string]: unknown;
}

// AuthenticateResult
interface AuthenticateResult {
  user: User;
  profile: SAMLProfile;
  finalDestination?: string;  // was: returnTo
}

// SamlConfig
interface SamlConfig {
  callbackOrigin: string;     // was: returnToOrigin
  callbackPath?: string;      // was: returnToPath
  // ... other fields unchanged
}
```

---

## v1.x → v2.0 Migration

This section helps you migrate from ADAPT Auth SDK v1.x to v2.0.

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

// v2.0+
const auth = createAdaptNext({
  saml: {
    issuer: 'your-entity',
    idpCert: 'cert-data',
    callbackOrigin: 'https://your-app.com',
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

| v1.x Variable | v2.0+ Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `ADAPT_AUTH_SAML_ENTITY` | `ADAPT_AUTH_SAML_ENTITY` | ✅ **Same** | SAML entity ID (required) |
| `ADAPT_AUTH_SAML_CERT` | `ADAPT_AUTH_SAML_CERT` | ✅ **Same** | IdP certificate (required) |
| `ADAPT_AUTH_SESSION_SECRET` | `ADAPT_AUTH_SESSION_SECRET` | ✅ **Same** | Session encryption secret (required) |
| `ADAPT_AUTH_SAML_RETURN_ORIGIN` | `ADAPT_AUTH_SAML_CALLBACK_ORIGIN` | 🔄 **Renamed** | Application base URL (required) |
| `ADAPT_AUTH_SESSION_EXPIRES_IN` | `ADAPT_AUTH_SESSION_EXPIRES_IN` | ✅ **Same** | Sessions default to expire when browser closes |


### Optional Variables (Still Supported)

| v1.x Variable | v2.0+ Variable | Status | Notes |
|---------------|---------------|--------|-------|
| `ADAPT_AUTH_SAML_SP_URL` | `ADAPT_AUTH_SAML_SP_URL` | ✅ **Same** | Service Provider login URL |
| `ADAPT_AUTH_SAML_RETURN_PATH` | `ADAPT_AUTH_SAML_CALLBACK_PATH` | 🔄 **Renamed** | ACS path component |
| `ADAPT_AUTH_SAML_DECRYPTION_KEY` | `ADAPT_AUTH_SAML_DECRYPTION_KEY` | ✅ **Same** | Private key for decryption |
| `ADAPT_AUTH_SESSION_NAME` | `ADAPT_AUTH_SESSION_NAME` | ✅ **Same** | Session cookie name |

### Deprecated Variables (No Longer Used)

| v1.x Variable | v2.0+ Equivalent | Status | Migration Notes |
|---------------|-----------------|--------|-----------------|
| `ADAPT_AUTH_SAML_RETURN_URL` | *Not used* | ❌ **Removed** | Use `ADAPT_AUTH_SAML_CALLBACK_ORIGIN` + `ADAPT_AUTH_SAML_CALLBACK_PATH` |
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
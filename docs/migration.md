# Migration Guide

This guide helps you migrate between ADAPT Auth SDK versions.

---

## v2.x → v3.0 Migration

Version 3.0 upgrades the underlying session library to `iron-session` v9. The public API is unchanged.

### Summary of Changes

| What Changed | v2.x | v3.0 |
|--------------|------|------|
| Minimum Node.js | 18 | 22.13 |
| `iron-session` | v8 | v9 |
| Unreadable session cookie | `getSession()` returned an empty object | `getSession()` returns `null` |
| `Date` values in session data | Silently converted to strings | Throws an error when saving |

### ⚠️ Breaking Change: Node.js 22.13 or Higher

`iron-session` v9 is ESM-only. The SDK's CommonJS build still works, because Node.js 22.13+ can `require()` ES modules natively. Upgrade your runtime (including serverless function runtimes) before upgrading the SDK.

### ⚠️ Breaking Change: Store Dates as Numbers or Strings

If you put `Date` objects in `meta`, save them as timestamps or ISO strings instead:

```typescript
// v2.x: silently stored as a string, read back as a string (not a Date)
await sessionManager.updateSession({ meta: { lastSeen: new Date() } });

// v3.0
await sessionManager.updateSession({ meta: { lastSeen: Date.now() } });
```

### Behavior Fix: Invalid Cookies Return `null`

When a session cookie could not be decrypted (for example, after rotating `ADAPT_AUTH_SESSION_SECRET`, or if the cookie was tampered with), v2.x `getSession()` returned an empty object with no `user`. Code that checked `if (session)` treated that visitor as signed in. v3.0 returns `null`, which matches the documented return type. `isAuthenticated()` and `getUser()` already behaved correctly.

### Existing Sessions Are Preserved

Cookies created by v2.x are readable by v3.0, and cookies created by v3.0 are readable by v2.x. Users stay signed in across the upgrade, and you can roll back without signing anyone out.

### Quick Migration Checklist

- [ ] Run on Node.js 22.13 or higher
- [ ] Replace any `Date` objects in session `meta` with `Date.now()` or `.toISOString()`
- [ ] If you call `getSession()` directly, make sure you handle `null`

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
| RelayState payload | `{ return_to: string }` | `{ entity, returnTo, finalDestination }` |

### ⚠️ Breaking Change: RelayState Payload Structure

If your code manually parses or generates RelayState, be aware of these changes:

```typescript
// v2.0 RelayState payload (snake_case, simple)
interface RelayStatePayload {
  return_to?: string;  // Final destination URL
}

// v2.1 RelayState payload (camelCase, expanded)
interface RelayStatePayload {
  entity?: string;           // SAML entity ID
  returnTo?: string;         // Callback URL (where IdP posts back)
  finalDestination?: string; // Where user goes after auth
}
```

**Key differences:**
- `return_to` → renamed to `finalDestination` (camelCase)
- New `returnTo` field contains the **callback URL** (ACS endpoint), not the final destination
- New `entity` field contains the SAML entity ID
- All keys are now camelCase for consistency

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
- [ ] Update any code that manually parses RelayState (structure changed significantly)
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
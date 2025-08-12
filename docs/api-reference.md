# API Reference

Complete API documentation for the ADAPT Auth SDK.

## Core Classes

### SAMLProvider

The SAML authentication provider for Stanford WebAuth integration.

#### Constructor

```typescript
constructor(config: SamlConfig, logger?: Logger)
```

**Parameters:**
- `config: SamlConfig` - SAML configuration object
- `logger?: Logger` - Optional logger instance

#### Methods

##### authenticate(returnTo?: string): Promise<{ redirectUrl: string; relayState: string }>

Initiates SAML authentication flow.

**Parameters:**
- `returnTo?: string` - Optional URL to redirect to after authentication

**Returns:**
- `redirectUrl: string` - URL to redirect user to IdP
- `relayState: string` - Signed RelayState token

**Example:**
```typescript
const samlProvider = new SAMLProvider(config);
const { redirectUrl } = await samlProvider.authenticate('/dashboard');
// Redirect user to redirectUrl
```

##### handleCallback(body: string, relayState?: string): Promise<{ user: User; returnTo?: string }>

Processes SAML callback from IdP.

**Parameters:**
- `body: string` - URL-encoded form body containing SAMLResponse
- `relayState?: string` - RelayState parameter from callback

**Returns:**
- `user: User` - Authenticated user object
- `returnTo?: string` - URL to redirect to (if provided in RelayState)

**Throws:**
- `SAMLError` - If SAML validation fails
- `AuthError` - For general authentication errors

**Example:**
```typescript
const formData = await request.formData();
const body = new URLSearchParams(formData).toString();
const relayState = formData.get('RelayState');

const { user, returnTo } = await samlProvider.handleCallback(body, relayState);
```

---

### SessionManager

Framework-agnostic session management using encrypted cookies.

#### Constructor

```typescript
constructor(cookieStore: CookieStore, config: SessionConfig, logger?: Logger)
```

**Parameters:**
- `cookieStore: CookieStore` - Cookie storage implementation
- `config: SessionConfig` - Session configuration
- `logger?: Logger` - Optional logger instance

#### Methods

##### getSession(): Promise<Session | null>

Retrieves current session from cookie.

**Returns:**
- `Session | null` - Current session or null if not authenticated

**Example:**
```typescript
const session = await sessionManager.getSession();
if (session) {
  console.log('User:', session.user.name);
}
```

##### createSession(user: User, meta?: Record<string, unknown>): Promise<void>

Creates a new session and sets cookie.

**Parameters:**
- `user: User` - User object to store in session
- `meta?: Record<string, unknown>` - Optional metadata

**Throws:**
- `SessionError` - If session creation fails or cookie is too large

**Example:**
```typescript
await sessionManager.createSession(user, {
  loginTime: Date.now(),
  userAgent: request.headers.get('user-agent'),
});
```

##### destroySession(): Promise<void>

Destroys current session and clears cookie.

**Example:**
```typescript
await sessionManager.destroySession();
```

##### updateSession(updates: Partial<Session>): Promise<void>

Updates existing session with new data.

**Parameters:**
- `updates: Partial<Session>` - Partial session data to merge

**Throws:**
- `SessionError` - If no existing session or update fails

**Example:**
```typescript
await sessionManager.updateSession({
  meta: { lastActivity: Date.now() },
});
```

---

### AdaptNext (Next.js Integration)

Simplified authentication wrapper for Next.js App Router.

#### Constructor

```typescript
constructor(config: AdaptAuthConfig)
```

**Parameters:**
- `config: AdaptAuthConfig` - Complete authentication configuration

#### Methods

##### getSession(request: Request): Promise<Session | null>

Gets session from Next.js request.

**Parameters:**
- `request: Request` - Next.js request object

**Returns:**
- `Session | null` - Current session or null

**Example:**
```typescript
// In route handler
export async function GET(request: Request) {
  const session = await auth.getSession(request);
  if (!session) {
    return Response.redirect('/api/auth/login');
  }
  return Response.json(session.user);
}
```

##### login(request: Request): Promise<Response>

Initiates SAML login flow.

**Parameters:**
- `request: Request` - Next.js request object

**Returns:**
- `Response` - Redirect response to IdP

**Example:**
```typescript
// In /api/auth/login/route.ts
export async function GET(request: Request) {
  return auth.login(request);
}
```

##### handleCallback(request: Request): Promise<Response>

Handles SAML callback and creates session.

**Parameters:**
- `request: Request` - Next.js request object with SAML response

**Returns:**
- `Response` - Redirect response to post-login URL

**Example:**
```typescript
// In /api/auth/acs/route.ts
export async function POST(request: Request) {
  return auth.handleCallback(request);
}
```

##### logout(request: Request): Promise<Response>

Logs out user and destroys session.

**Parameters:**
- `request: Request` - Next.js request object

**Returns:**
- `Response` - Redirect response to post-logout URL

**Example:**
```typescript
// In /api/auth/logout/route.ts
export async function POST(request: Request) {
  return auth.logout(request);
}
```

---

## Cookie Store Implementations

### NextCookieStore

Cookie store implementation for Next.js.

```typescript
createNextCookieStore(request: Request, response?: Response): CookieStore
```

### ExpressCookieStore

Cookie store implementation for Express.js.

```typescript
createExpressCookieStore(req: express.Request, res: express.Response): CookieStore
```

### WebCookieStore

Generic cookie store for Web API frameworks.

```typescript
createWebCookieStore(request: Request, response: Response): CookieStore
```

---

## Utility Functions

### AuthUtils

Static utility class for cryptographic operations.

#### Methods

##### generateCSRFToken(): string

Generates a cryptographically secure CSRF token.

**Returns:**
- `string` - Base64-encoded CSRF token

##### validateCSRFToken(token: string, session: Session): boolean

Validates a CSRF token against the session.

**Parameters:**
- `token: string` - CSRF token to validate
- `session: Session` - Current session

**Returns:**
- `boolean` - True if token is valid

##### createHMAC(data: string, secret: string): string

Creates HMAC-SHA256 signature.

**Parameters:**
- `data: string` - Data to sign
- `secret: string` - HMAC secret

**Returns:**
- `string` - Base64-encoded HMAC signature

##### verifyHMAC(data: string, signature: string, secret: string): boolean

Verifies HMAC signature.

**Parameters:**
- `data: string` - Original data
- `signature: string` - Signature to verify
- `secret: string` - HMAC secret

**Returns:**
- `boolean` - True if signature is valid

##### sanitizeReturnUrl(url: string, allowedOrigins?: string[]): string | null

Sanitizes and validates return URLs.

**Parameters:**
- `url: string` - URL to sanitize
- `allowedOrigins?: string[]` - Allowed origin list

**Returns:**
- `string | null` - Sanitized URL or null if invalid

---

## Type Definitions

### Core Types

#### User

```typescript
interface User {
  id: string;
  email?: string;
  name?: string;
  imageUrl?: string;
  [key: string]: unknown;
}
```

#### Session

```typescript
interface Session {
  user: User;
  meta?: Record<string, unknown>;
  issuedAt: number;
  expiresAt: number;
}
```

#### SamlConfig

```typescript
interface SamlConfig {
  // Required
  issuer: string;
  idpCert: string;
  returnToOrigin: string;

  // Optional
  serviceProviderLoginUrl?: string;
  returnToPath?: string;
  includeReturnTo?: boolean;
  relayStateMaxAge?: number;
  relayStateSecret?: string;
  decryptionPvk?: string;
  wantAssertionsSigned?: boolean;
  wantAuthnResponseSigned?: boolean;
  acceptedClockSkewMs?: number;
}
```

#### SessionConfig

```typescript
interface SessionConfig {
  name: string;
  secret: string;
  cookie?: {
    httpOnly?: boolean;
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    path?: string;
    domain?: string;
    maxAge?: number;
  };
  cookieSizeThreshold?: number;
}
```

#### AuthCallbacks

```typescript
interface AuthCallbacks {
  mapProfile?: (profile: any) => Promise<User> | User;
  signIn?: (params: { user: User; profile: any }) => Promise<void> | void;
  signOut?: (params: { session: Session }) => Promise<void> | void;
  session?: (params: {
    session: Session;
    user: User;
    req: Request;
  }) => Promise<Session> | Session;
}
```

### Error Types

#### AuthError

Base error class for authentication errors.

```typescript
class AuthError extends Error {
  code: string;
  constructor(message: string, code: string = 'AUTH_ERROR');
}
```

#### SAMLError

SAML-specific error class.

```typescript
class SAMLError extends AuthError {
  issuer?: string;
  constructor(message: string, code: string = 'SAML_ERROR', issuer?: string);
}
```

#### SessionError

Session-specific error class.

```typescript
class SessionError extends AuthError {
  sessionName?: string;
  constructor(message: string, code: string = 'SESSION_ERROR', sessionName?: string);
}
```

### Logger Interface

```typescript
interface Logger {
  debug(message: string, meta?: any): void;
  info(message: string, meta?: any): void;
  warn(message: string, meta?: any): void;
  error(message: string, error?: any): void;
}
```

### Cookie Store Interface

```typescript
interface CookieStore {
  get(name: string): Promise<string | undefined>;
  set(name: string, value: string, options: any): Promise<void>;
  delete(name: string): Promise<void>;
}
```

---

## Configuration Factory Functions

### createAdaptNext

Creates a configured AdaptNext instance for Next.js.

```typescript
function createAdaptNext(config: AdaptAuthConfig): AdaptNext
```

### createSAMLProvider

Creates a configured SAML provider.

```typescript
function createSAMLProvider(config: SamlConfig, logger?: Logger): SAMLProvider
```

### createSessionManager

Creates a configured session manager.

```typescript
function createSessionManager(
  cookieStore: CookieStore,
  config: SessionConfig,
  logger?: Logger
): SessionManager
```

---

## Environment Configuration

The SDK can be configured using environment variables:

### Required Variables

- `ADAPT_AUTH_SAML_ENTITY` - SAML entity ID
- `ADAPT_AUTH_SAML_CERT` - IdP certificate
- `ADAPT_AUTH_SAML_RETURN_ORIGIN` - Application base URL
- `ADAPT_AUTH_SESSION_SECRET` - Session encryption secret

### Optional Variables

- `ADAPT_AUTH_SAML_SP_URL` - Service provider login URL
- `ADAPT_AUTH_SAML_RETURN_PATH` - ACS path
- `ADAPT_AUTH_SAML_DECRYPTION_KEY` - SAML decryption key
- `ADAPT_AUTH_RELAY_STATE_SECRET` - RelayState signing secret
- `ADAPT_AUTH_SESSION_NAME` - Session cookie name

---

## Usage Examples

### Basic Next.js Setup

```typescript
// lib/auth.ts
import { createAdaptNext } from 'adapt-auth-sdk';

export const auth = createAdaptNext({
  saml: {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  },
});

// app/api/auth/login/route.ts
export async function GET(request: Request) {
  return auth.login(request);
}

// app/api/auth/acs/route.ts
export async function POST(request: Request) {
  return auth.handleCallback(request);
}

// app/api/auth/logout/route.ts
export async function POST(request: Request) {
  return auth.logout(request);
}
```

### Express.js Setup

```typescript
import express from 'express';
import { SAMLProvider, SessionManager, createExpressCookieStore } from 'adapt-auth-sdk';

const app = express();

const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
});

// Middleware to create session manager per request
app.use((req, res, next) => {
  const cookieStore = createExpressCookieStore(req, res);
  req.sessionManager = new SessionManager(cookieStore, {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  });
  next();
});

// Routes
app.get('/auth/login', async (req, res) => {
  const { redirectUrl } = await samlProvider.authenticate();
  res.redirect(redirectUrl);
});

app.post('/auth/acs', express.urlencoded({ extended: true }), async (req, res) => {
  try {
    const { user, returnTo } = await samlProvider.handleCallback(
      new URLSearchParams(req.body).toString(),
      req.body.RelayState
    );

    await req.sessionManager.createSession(user);
    res.redirect(returnTo || '/dashboard');
  } catch (error) {
    res.status(401).send('Authentication failed');
  }
});
```

This API reference provides comprehensive documentation for all classes, methods, types, and configuration options available in the ADAPT Auth SDK.

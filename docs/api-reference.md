# API Reference

Complete API documentation for the ADAPT Auth SDK.

## Core Classes

### AdaptNext (Next.js Integration)

Simplified authentication wrapper for Next.js App Router.

#### Constructor

```typescript
constructor(config: AdaptNextConfig)
```

#### Methods

##### login(options?: LoginOptions): Promise<Response>

Initiates SAML login flow.

**Parameters:**
- `options?: LoginOptions` - Optional login configuration

**Returns:**
- `Response` - Redirect response to IdP

##### authenticate(request: Request): Promise<{ user: User; session: Session; returnTo?: string }>

Handles SAML callback and creates session.

**Parameters:**
- `request: Request` - Next.js request object with SAML response

**Returns:**
- Object containing authenticated user, session, and optional returnTo URL

##### getSession(): Promise<Session | null>

Gets current session.

##### getUser(): Promise<User | null>

Gets current authenticated user.

##### isAuthenticated(): Promise<boolean>

Checks if user is authenticated.

##### logout(): Promise<void>

Logs out user and destroys session.

##### updateSession(updates: Partial<Session>): Promise<Session | null>

Updates existing session with new data.

**Parameters:**
- `updates: Partial<Session>` - Partial session data to merge

##### refreshSession(): Promise<Session | null>

Refreshes session (sliding expiration).

##### getLoginUrl(options?: LoginOptions): Promise<string>

Creates login URL without redirecting.

##### auth(handler: RouteHandler): RouteHandler

Middleware function for protecting routes.

### SAMLProvider

The SAML authentication provider for Stanford WebAuth integration.

#### Constructor

```typescript
constructor(config: SamlConfig, logger?: Logger)
```

#### Methods

##### getLoginUrl(options?: LoginOptions): Promise<string>

Generate login URL for SAML authentication.

##### authenticate(options: AuthenticateOptions): Promise<{ user: User; profile: SAMLProfile; returnTo?: string }>

Authenticate SAML response from IdP.

##### getConfig(): Record<string, unknown>

Get SAML provider configuration (for debugging).

### SessionManager

Framework-agnostic session management using encrypted cookies.

#### Constructor

```typescript
constructor(cookieStore: CookieStore, config: SessionConfig, logger?: Logger)
```

#### Methods

##### getSession(): Promise<Session | null>

Retrieves current session from cookie.

##### createSession(user: User, meta?: Record<string, unknown>): Promise<Session>

Creates a new session and sets cookie.

##### updateSession(updates: Partial<Session>): Promise<Session | null>

Updates existing session with new data.

##### destroySession(): Promise<void>

Destroys current session and clears cookie.

##### refreshSession(): Promise<Session | null>

Refresh session with updated timestamps.

##### isAuthenticated(): Promise<boolean>

Check if user is authenticated.

##### getUser(): Promise<User | null>

Get current authenticated user.

### EdgeSessionReader

Ultra-fast session validation for edge functions.

#### Constructor

```typescript
constructor(secret: string, cookieName?: string)
```

#### Methods

##### getSessionFromRequest(request: Request): Promise<Session | null>

Get session from request in edge environment.

##### getSessionFromCookieHeader(cookieHeader: string): Promise<Session | null>

Parse session from cookie header string.

##### isAuthenticated(request: Request): Promise<boolean>

Check if request is authenticated.

##### getUser(request: Request): Promise<User | null>

Get user from request.

##### getUserId(request: Request): Promise<string | null>

Get user ID from request.

## Factory Functions

### createAdaptNext

```typescript
function createAdaptNext(config: AdaptNextConfig): AdaptNext
```

### createSAMLProvider

```typescript
function createSAMLProvider(config?: Partial<SamlConfig>, logger?: Logger): SAMLProvider
```

### createExpressCookieStore

```typescript
function createExpressCookieStore(req: express.Request, res: express.Response): CookieStore
```

### createWebCookieStore

```typescript
function createWebCookieStore(request: Request, response: Response): CookieStore
```

### createEdgeSessionReader

```typescript
function createEdgeSessionReader(secret?: string, cookieName?: string): EdgeSessionReader
```

## Utility Functions

### Client-side Authentication Check

```typescript
function isAuthenticated(cookieName: string): boolean
```

### Edge Utilities

```typescript
function getUserIdFromRequest(request: Request, secret?: string): Promise<string | null>
function getUserIdFromCookie(cookieValue: string, secret: string): Promise<string | null>
```

### Next.js Utilities

```typescript
function getSessionFromNextRequest(request: Request, secret?: string, cookieName?: string): Promise<Session | null>
function getSessionFromNextCookies(cookies: NextCookies, secret?: string, cookieName?: string): Promise<Session | null>
```

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

  // Optional with defaults
  serviceProviderLoginUrl?: string;
  returnToPath?: string;
  includeReturnTo?: boolean;
  privateKey?: string;
  decryptionPvk?: string;
  audience?: string;
  wantAssertionsSigned?: boolean;
  wantAuthnResponseSigned?: boolean;
  acceptedClockSkewMs?: number;
  signatureAlgorithm?: string;
  identifierFormat?: string;
  allowCreate?: boolean;
  additionalParams?: Record<string, unknown>;
  additionalAuthorizeParams?: Record<string, unknown>;
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

#### AdaptNextConfig

```typescript
interface AdaptNextConfig {
  saml: SamlConfig;
  session: SessionConfig;
  callbacks?: AuthCallbacks;
  logger?: Logger;
  verbose?: boolean;
}
```

#### AuthCallbacks

```typescript
interface AuthCallbacks {
  mapProfile?: (profile: SAMLProfile) => Promise<User> | User;
  signIn?: (params: { user: User; profile: SAMLProfile }) => Promise<void> | void;
  signOut?: (params: { session: Session }) => Promise<void> | void;
  session?: (params: { session: Session; user: User; req: Request }) => Promise<void> | void;
}
```

## Error Classes

All error classes extend `AuthError` from the types module.

### SAMLError

```typescript
class SAMLError extends AuthError {
  constructor(message: string, samlCode: string, issuer?: string, statusCode?: number)
}
```

### SessionError

```typescript
class SessionError extends AuthError {
  constructor(message: string, sessionCode: string, sessionName?: string, statusCode?: number)
}
```

### ConfigError

```typescript
class ConfigError extends AuthError {
  constructor(message: string, configCode: string, fieldName?: string, statusCode?: number)
}
```

### NetworkError

```typescript
class NetworkError extends AuthError {
  constructor(message: string, networkCode: string, operation?: string, originalError?: Error, statusCode?: number)
}
```

## Logger Classes

### DefaultLogger

Structured JSON logger with PII redaction.

```typescript
class DefaultLogger implements Logger {
  constructor(verbose?: boolean)
  debug(message: string, meta?: Record<string, unknown>): void
  info(message: string, meta?: Record<string, unknown>): void
  warn(message: string, meta?: Record<string, unknown>): void
  error(message: string, meta?: Record<string, unknown>): void
  setContext(context: Record<string, unknown>): void
}
```

### ConsoleLogger

Simple console logger with prefixes.

```typescript
class ConsoleLogger implements Logger
```

### SilentLogger

No-op logger for production.

```typescript
class SilentLogger implements Logger
```

## Usage Examples

### Basic Next.js Setup

```typescript
import { createAdaptNext } from 'adapt-auth-sdk';

export const auth = createAdaptNext({
  saml: {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
  },
  session: {
    name: 'adapt-auth',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  },
});

// app/api/auth/login/route.ts
export async function GET() {
  return auth.login({ returnTo: '/dashboard' });
}

// app/api/auth/callback/route.ts
export async function POST(request: Request) {
  const { user, returnTo } = await auth.authenticate(request);
  return Response.redirect(returnTo || '/dashboard');
}
```

### Express.js Setup

```typescript
import { SAMLProvider, SessionManager, createExpressCookieStore } from 'adapt-auth-sdk';

const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
});

app.get('/auth/login', async (req, res) => {
  const loginUrl = await samlProvider.getLoginUrl({ returnTo: '/dashboard' });
  res.redirect(loginUrl);
});

app.post('/auth/callback', async (req, res) => {
  const { user, returnTo } = await samlProvider.authenticate({ req });

  const cookieStore = createExpressCookieStore(req, res);
  const sessionManager = new SessionManager(cookieStore, {
    name: 'adapt-auth',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  });

  await sessionManager.createSession(user);
  res.redirect(returnTo || '/dashboard');
});
```

### Edge Function Session Validation

```typescript
import { createEdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  const reader = createEdgeSessionReader();
  const isAuthenticated = await reader.isAuthenticated(request);

  if (!isAuthenticated && request.nextUrl.pathname.startsWith('/protected')) {
    return Response.redirect(new URL('/api/auth/login', request.url));
  }
}
```

# Advanced Usage

This document covers advanced features and integration patterns for the ADAPT Auth SDK.

## Custom Session Management

### Session Enhancement

Add custom metadata to sessions safely:

```typescript
callbacks: {
  session: async ({ session, user, req }) => {
    // Add metadata while respecting cookie size limits
    const userRoles = await getUserRoles(user.id);
    const tenantInfo = await getTenantInfo(user.id);

    return {
      ...session,
      meta: {
        roles: userRoles.map(r => r.id), // Store IDs, not full objects
        tenantId: tenantInfo.id,
        lastActivity: Date.now(),
        userAgent: req.headers.get('user-agent')?.substring(0, 100), // Truncate
      }
    };
  }
}
```

### Dynamic Session Updates

Use the `updateSession` method to modify session data after initial authentication:

```typescript
// Update user preferences
export async function updateUserPreferences(request: Request, preferences: any) {
  const session = await auth.getSession(request);
  if (!session) return null;

  return await auth.updateSession({
    meta: {
      ...session.meta,
      preferences,
      lastUpdated: Date.now(),
    }
  });
}

// Track user activity
export async function trackUserActivity(request: Request, activity: string) {
  const session = await auth.getSession(request);
  if (!session) return;

  const currentActivities = session.meta?.activities || [];
  const recentActivities = currentActivities.slice(-9); // Keep last 9 + new one = 10

  await auth.updateSession({
    meta: {
      ...session.meta,
      activities: [...recentActivities, {
        action: activity,
        timestamp: Date.now(),
        path: new URL(request.url).pathname,
      }],
      lastActivity: Date.now(),
    }
  });
}

// Update user profile information
export async function updateUserProfile(request: Request, profileUpdates: Partial<User>) {
  const session = await auth.getSession(request);
  if (!session) return null;

  return await auth.updateSession({
    user: {
      ...session.user,
      ...profileUpdates,
    },
    meta: {
      ...session.meta,
      profileUpdated: Date.now(),
    }
  });
}

// Add role-based metadata
export async function addUserRoles(request: Request, roles: string[]) {
  const session = await auth.getSession(request);
  if (!session) return null;

  return await auth.updateSession({
    meta: {
      ...session.meta,
      roles,
      rolesUpdated: Date.now(),
    }
  });
}

// Complex metadata management
export async function manageUserContext(request: Request, context: {
  theme?: 'light' | 'dark';
  language?: string;
  timezone?: string;
  notifications?: boolean;
  features?: string[];
}) {
  const session = await auth.getSession(request);
  if (!session) return null;

  // Merge with existing context
  const existingContext = session.meta?.context || {};
  const updatedContext = { ...existingContext, ...context };

  return await auth.updateSession({
    meta: {
      ...session.meta,
      context: updatedContext,
      contextUpdated: Date.now(),
    }
  });
}
```

### Session Size Management

Keep sessions under the recommended size limit while updating:

```typescript
// Monitor and optimize session size
export async function updateSessionSafely(request: Request, updates: Partial<Session>) {
  const session = await auth.getSession(request);
  if (!session) return null;

  // Estimate size of updates
  const estimatedSize = JSON.stringify({ ...session, ...updates }).length;

  if (estimatedSize > 3500) { // Cookie size threshold
    console.warn('Session update may exceed size limit', {
      currentSize: JSON.stringify(session).length,
      estimatedSize,
      userId: session.user.id
    });

    // Trim older metadata if needed
    const trimmedMeta = trimSessionMetadata(session.meta);
    updates.meta = { ...trimmedMeta, ...updates.meta };
  }

  return await auth.updateSession(updates);
}

function trimSessionMetadata(meta: any) {
  if (!meta) return {};

  const trimmed = { ...meta };

  // Remove old activities (keep only recent 5)
  if (trimmed.activities && Array.isArray(trimmed.activities)) {
    trimmed.activities = trimmed.activities.slice(-5);
  }

  // Remove old tracking data
  delete trimmed.debugInfo;
  delete trimmed.detailedUserAgent;

  // Keep only essential data
  return {
    preferences: trimmed.preferences,
    theme: trimmed.theme,
    language: trimmed.language,
    roles: trimmed.roles,
    lastActivity: trimmed.lastActivity,
    activities: trimmed.activities,
  };
}
```

### Custom Cookie Stores

Implement custom cookie storage for specialized frameworks:

```typescript
import { CookieStore } from 'adapt-auth-sdk';

class CustomCookieStore implements CookieStore {
  constructor(private context: YourFrameworkContext) {}

  async get(name: string): Promise<string | undefined> {
    return this.context.cookies.get(name);
  }

  async set(name: string, value: string, options: any): Promise<void> {
    this.context.cookies.set(name, value, options);
  }

  async delete(name: string): Promise<void> {
    this.context.cookies.delete(name);
  }
}

// Use with SessionManager
const cookieStore = new CustomCookieStore(context);
const sessionManager = new SessionManager(cookieStore, sessionConfig);
```

## Advanced SAML Configuration

### Custom Attribute Mapping

Map complex SAML attributes to your user model:

```typescript
callbacks: {
  mapProfile: async (profile) => {
    // Handle multiple attribute formats
    const getAttr = (key: string) => {
      const value = profile[key];
      return Array.isArray(value) ? value[0] : value;
    };

    return {
      id: getAttr('encodedSUID'),
      email: `${getAttr('userName')}@stanford.edu`,
      name: `${getAttr('firstName')} ${getAttr('lastName')}`,

      // Map Stanford-specific attributes
      suid: getAttr('suid'),
      affiliation: getAttr('affiliation'),
      department: getAttr('department'),
      workgroup: getAttr('workgroup'),

      // Custom business logic
      isEmployee: getAttr('affiliation')?.includes('staff'),
      isStudent: getAttr('affiliation')?.includes('student'),

      // Role mapping
      roles: await mapStanfordRoles(getAttr('workgroup')),
    };
  }
}
```

### Multi-Environment Configuration

Handle different environments cleanly:

```typescript
const createAuthConfig = (env: 'dev' | 'staging' | 'production') => {
  const baseConfig = {
    saml: {
      issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
      idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
      returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
    },
    session: {
      name: 'adapt-auth-session',
      secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
    },
  };

  const envConfigs = {
    dev: {
      saml: {
        serviceProviderLoginUrl: 'https://adapt-sso-dev.stanford.edu/api/sso/login',
        acceptedClockSkewMs: 120000, // More lenient for dev
      },
      verbose: true,
    },
    staging: {
      saml: {
        serviceProviderLoginUrl: 'https://adapt-sso-uat.stanford.edu/api/sso/login',
      },
      verbose: false,
    },
    production: {
      saml: {
        serviceProviderLoginUrl: 'https://adapt-sso.stanford.edu/api/sso/login',
        wantAssertionsSigned: true,
        wantAuthnResponseSigned: true,
      },
      verbose: false,
    },
  };

  return { ...baseConfig, ...envConfigs[env] };
};

export const auth = createAdaptNext(createAuthConfig(process.env.NODE_ENV as any));
```

## Error Handling and Recovery

### Comprehensive Error Handling

```typescript
import { AuthError, SAMLError, SessionError } from 'adapt-auth-sdk';

export async function handleAuthRequest(request: Request) {
  try {
    return await auth.handleCallback(request);
  } catch (error) {
    if (error instanceof SAMLError) {
      // SAML-specific errors (signature validation, etc.)
      logger.error('SAML validation failed', {
        code: error.code,
        message: error.message,
        samlIssuer: error.issuer,
      });

      return new Response('Authentication failed', { status: 401 });
    }

    if (error instanceof SessionError) {
      // Session-related errors (encryption, size, etc.)
      logger.error('Session error', {
        code: error.code,
        sessionName: error.sessionName,
      });

      // Clear potentially corrupted session
      return auth.logout(request);
    }

    if (error instanceof AuthError) {
      // General authentication errors
      logger.error('Authentication error', error);
      return new Response('Authentication failed', { status: 401 });
    }

    // Unexpected errors
    logger.error('Unexpected authentication error', error);
    return new Response('Internal error', { status: 500 });
  }
}
```

### Graceful Degradation

```typescript
// Fallback authentication for system maintenance
export async function getSessionWithFallback(request: Request) {
  try {
    return await auth.getSession(request);
  } catch (error) {
    if (process.env.MAINTENANCE_MODE === 'true') {
      // Return read-only session during maintenance
      return {
        user: { id: 'maintenance', name: 'System Maintenance' },
        isMaintenanceMode: true,
      };
    }
    throw error;
  }
}
```

## Performance Optimization

### Session Caching Strategy

```typescript
// Cache user data to reduce session size
class UserDataCache {
  private cache = new Map<string, any>();
  private readonly TTL = 5 * 60 * 1000; // 5 minutes

  async get(userId: string) {
    const cached = this.cache.get(userId);
    if (cached && Date.now() - cached.timestamp < this.TTL) {
      return cached.data;
    }

    // Fetch fresh data
    const data = await fetchUserData(userId);
    this.cache.set(userId, { data, timestamp: Date.now() });
    return data;
  }
}

// Use minimal session data
callbacks: {
  session: async ({ session, user }) => ({
    ...session,
    meta: {
      cacheKey: user.id, // Store only reference
      roles: (await userCache.get(user.id))?.roleIds,
    }
  })
}
```

### Lazy Loading User Data

```typescript
// Load detailed user data on demand
export class UserService {
  static async getFullUserProfile(session: Session) {
    if (!session.user.id) return null;

    // Use cache if available
    const cached = await redis.get(`user:${session.user.id}`);
    if (cached) return JSON.parse(cached);

    // Fetch from database
    const profile = await db.user.findUnique({
      where: { id: session.user.id },
      include: { roles: true, permissions: true }
    });

    // Cache for future requests
    await redis.setex(`user:${session.user.id}`, 300, JSON.stringify(profile));

    return profile;
  }
}
```

## Advanced Routing Patterns

### Middleware Composition

```typescript
// Next.js middleware with authentication
import { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // Public routes
  if (request.nextUrl.pathname.startsWith('/public')) {
    return;
  }

  // Auth routes
  if (request.nextUrl.pathname.startsWith('/api/auth')) {
    return;
  }

  // Protected routes
  const session = await auth.getSession(request);

  if (!session) {
    const loginUrl = new URL('/api/auth/login', request.url);
    loginUrl.searchParams.set('returnTo', request.url);
    return Response.redirect(loginUrl);
  }

  // Role-based protection
  if (request.nextUrl.pathname.startsWith('/admin')) {
    const userProfile = await UserService.getFullUserProfile(session);

    if (!userProfile?.roles.some(r => r.name === 'admin')) {
      return new Response('Forbidden', { status: 403 });
    }
  }
}
```

### Dynamic Route Protection

```typescript
// Route-level authorization
export function withAuth<T extends any[]>(
  handler: (...args: T) => Promise<Response>,
  options: {
    requireRoles?: string[];
    requirePermissions?: string[];
  } = {}
) {
  return async (...args: T): Promise<Response> => {
    const [request] = args;

    const session = await auth.getSession(request);
    if (!session) {
      return Response.redirect('/api/auth/login');
    }

    // Check roles if required
    if (options.requireRoles?.length) {
      const userProfile = await UserService.getFullUserProfile(session);
      const hasRole = options.requireRoles.some(role =>
        userProfile?.roles.some(r => r.name === role)
      );

      if (!hasRole) {
        return new Response('Insufficient permissions', { status: 403 });
      }
    }

    return handler(...args);
  };
}

// Usage
export const POST = withAuth(async (request: Request) => {
  // Handler logic
}, { requireRoles: ['admin'] });
```

## Logging and Monitoring

### Custom Logger Implementation

```typescript
import { Logger } from 'adapt-auth-sdk';

class ApplicationLogger implements Logger {
  constructor(
    private winston: any, // Your winston instance
    private sentryLogger: any // Your Sentry instance
  ) {}

  debug(message: string, meta?: any): void {
    this.winston.debug(message, meta);
  }

  info(message: string, meta?: any): void {
    this.winston.info(message, meta);

    // Send important events to monitoring
    if (meta?.event === 'signin' || meta?.event === 'signout') {
      this.sentryLogger.addBreadcrumb({
        message,
        category: 'auth',
        data: meta,
      });
    }
  }

  warn(message: string, meta?: any): void {
    this.winston.warn(message, meta);
    this.sentryLogger.captureMessage(message, 'warning');
  }

  error(message: string, error?: any): void {
    this.winston.error(message, error);
    this.sentryLogger.captureException(error || new Error(message));
  }
}

// Use custom logger
const auth = createAdaptNext({
  // ... config
  logger: new ApplicationLogger(winston, Sentry),
});
```

### Metrics Collection

```typescript
// Collect authentication metrics
class AuthMetrics {
  private metrics = {
    loginAttempts: 0,
    successfulLogins: 0,
    failedLogins: 0,
    sessionCreations: 0,
    sessionErrors: 0,
  };

  increment(metric: keyof typeof this.metrics) {
    this.metrics[metric]++;

    // Send to your metrics system
    this.sendToDatadog(metric, 1);
  }

  getMetrics() {
    return { ...this.metrics };
  }

  private sendToDatadog(metric: string, value: number) {
    // Implementation depends on your metrics system
  }
}

const metrics = new AuthMetrics();

// Integrate with callbacks
callbacks: {
  signIn: async ({ user }) => {
    metrics.increment('successfulLogins');
  },

  // Custom error tracking
  error: async ({ error, context }) => {
    if (context === 'session') {
      metrics.increment('sessionErrors');
    } else {
      metrics.increment('failedLogins');
    }
  }
}
```

## Testing Strategies

### Mocking SAML Responses

```typescript
// Test helper for SAML responses
export class SAMLTestHelper {
  static createMockProfile(overrides: Partial<any> = {}) {
    return {
      encodedSUID: 'test123',
      userName: 'testuser',
      firstName: 'Test',
      lastName: 'User',
      affiliation: 'staff',
      ...overrides,
    };
  }

  static createMockSAMLResponse(profile: any) {
    // Create valid SAML response for testing
    // This would use a proper SAML library in practice
  }
}

// Test authentication flow
describe('Authentication Flow', () => {
  it('should handle successful SAML authentication', async () => {
    const mockProfile = SAMLTestHelper.createMockProfile();
    const samlResponse = SAMLTestHelper.createMockSAMLResponse(mockProfile);

    const result = await auth.handleCallback(
      new Request('https://test.com/api/auth/acs', {
        method: 'POST',
        body: new URLSearchParams({ SAMLResponse: samlResponse }),
      })
    );

    expect(result.status).toBe(302); // Redirect after successful auth
  });
});
```

### Integration Testing

```typescript
// Test with real Stanford dev environment
describe('Stanford Integration', () => {
  beforeAll(() => {
    // Setup test configuration for Stanford dev environment
  });

  it('should integrate with Stanford WebAuth', async () => {
    // Test against actual Stanford dev IdP
    // This requires proper test credentials
  });
});
```

## Migration Patterns

### Gradual Migration

```typescript
// Migrate from existing auth system gradually
export class HybridAuthSystem {
  constructor(
    private adaptAuth: any, // ADAPT Auth SDK instance
    private legacyAuth: any // Your existing auth system
  ) {}

  async authenticate(request: Request) {
    // Try new system first
    try {
      return await this.adaptAuth.getSession(request);
    } catch (error) {
      // Fall back to legacy system
      return await this.legacyAuth.getSession(request);
    }
  }

  async migrateLegacySession(legacySession: any) {
    // Convert legacy session to new format
    const adaptSession = {
      user: {
        id: legacySession.userId,
        email: legacySession.email,
        name: legacySession.displayName,
      },
      meta: {
        migratedFrom: 'legacy',
        migrationDate: Date.now(),
      }
    };

    return adaptSession;
  }
}
```

This advanced usage guide provides patterns for complex authentication scenarios while maintaining security and performance best practices.

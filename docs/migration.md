# Migration Guide

This guide helps you migrate from existing authentication systems to the ADAPT Auth SDK v2.0.

## Migration from v1.x

### Overview of Changes

ADAPT Auth SDK v2.0 introduces significant architectural changes:

- **Framework Agnostic**: No longer tied to specific frameworks
- **Modern TypeScript**: Full TypeScript rewrite with strict typing
- **Enhanced Security**: HMAC-signed RelayState, CSRF protection
- **Simplified API**: Cleaner, more intuitive interfaces
- **Cookie-Only Sessions**: No server-side session storage required

### Breaking Changes

#### 1. Import Statements

**v1.x:**
```typescript
import { AdaptAuth } from 'adapt-auth-sdk';
```

**v2.0:**
```typescript
// For Next.js
import { createAdaptNext } from 'adapt-auth-sdk';

// For other frameworks
import { SAMLProvider, SessionManager } from 'adapt-auth-sdk';
```

#### 2. Configuration Structure

**v1.x:**
```typescript
const auth = new AdaptAuth({
  entityId: 'your-entity',
  certificate: 'cert-data',
  sessionSecret: 'secret',
  // Other options...
});
```

**v2.0:**
```typescript
const auth = createAdaptNext({
  saml: {
    issuer: 'your-entity',
    idpCert: 'cert-data',
    returnToOrigin: 'https://your-app.com',
  },
  session: {
    name: 'session-name',
    secret: 'secret',
  },
});
```

#### 3. Method Names and Signatures

**v1.x:**
```typescript
// Initiate login
auth.login(req, res);

// Handle callback
auth.callback(req, res);

// Get user
const user = auth.getUser(req);
```

**v2.0:**
```typescript
// Initiate login
const response = await auth.login(request);

// Handle callback
const response = await auth.handleCallback(request);

// Get session
const session = await auth.getSession(request);
const user = session?.user;
```

### Step-by-Step Migration

#### Step 1: Update Dependencies

```bash
npm uninstall adapt-auth-sdk@1.x
npm install adapt-auth-sdk@2.0
```

#### Step 2: Update Configuration

Create new configuration object:

```typescript
// Before (v1.x)
const authConfig = {
  entityId: process.env.SAML_ENTITY_ID,
  certificate: process.env.SAML_CERTIFICATE,
  sessionSecret: process.env.SESSION_SECRET,
  loginUrl: process.env.SAML_LOGIN_URL,
};

// After (v2.0)
const authConfig = {
  saml: {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT,
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN,
    serviceProviderLoginUrl: process.env.ADAPT_AUTH_SAML_SP_URL,
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET,
  },
};
```

#### Step 3: Update Route Handlers

**Next.js App Router Migration:**

```typescript
// Before (v1.x - Pages Router)
// pages/api/auth/login.ts
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  return auth.login(req, res);
}

// After (v2.0 - App Router)
// app/api/auth/login/route.ts
export async function GET(request: Request) {
  return auth.login(request);
}
```

```typescript
// Before (v1.x)
// pages/api/auth/acs.ts
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  return auth.callback(req, res);
}

// After (v2.0)
// app/api/auth/acs/route.ts
export async function POST(request: Request) {
  return auth.handleCallback(request);
}
```

#### Step 4: Update Session Handling

```typescript
// Before (v1.x)
export default function protectedPage({ req, user }) {
  if (!user) {
    return <div>Not authenticated</div>;
  }
  return <div>Hello, {user.name}</div>;
}

export async function getServerSideProps({ req }) {
  const user = auth.getUser(req);
  return { props: { user } };
}

// After (v2.0)
export default function ProtectedPage() {
  const { data: session } = useSWR('/api/session', fetchSession);

  if (!session) {
    return <div>Not authenticated</div>;
  }

  return <div>Hello, {session.user.name}</div>;
}

// app/api/session/route.ts
export async function GET(request: Request) {
  const session = await auth.getSession(request);
  return Response.json(session);
}
```

### Migration Utilities

#### Automatic Configuration Migration

Use this utility to help migrate your configuration:

```typescript
// migration-helper.ts
export function migrateV1Config(v1Config: any) {
  return {
    saml: {
      issuer: v1Config.entityId,
      idpCert: v1Config.certificate,
      returnToOrigin: v1Config.returnToOrigin || process.env.APP_URL,
      serviceProviderLoginUrl: v1Config.loginUrl,
      // Map other SAML options...
    },
    session: {
      name: v1Config.sessionName || 'adapt-auth-session',
      secret: v1Config.sessionSecret,
      cookie: {
        secure: v1Config.secureCookies !== false,
        httpOnly: v1Config.httpOnlyCookies !== false,
        sameSite: v1Config.sameSite || 'lax',
      },
    },
    callbacks: {
      mapProfile: v1Config.profileMapper,
      signIn: v1Config.onSignIn,
      signOut: v1Config.onSignOut,
    },
  };
}
```

#### Session Data Migration

If you need to migrate existing session data:

```typescript
// session-migrator.ts
import { SessionManager } from 'adapt-auth-sdk';

export class SessionMigrator {
  constructor(
    private legacySessionStore: any,
    private newSessionManager: SessionManager
  ) {}

  async migrateSessions() {
    const legacySessions = await this.legacySessionStore.getAll();

    for (const legacySession of legacySessions) {
      const newSession = this.transformSession(legacySession);
      await this.newSessionManager.createSession(newSession.user, newSession.meta);
    }
  }

  private transformSession(legacySession: any) {
    return {
      user: {
        id: legacySession.userId,
        email: legacySession.email,
        name: legacySession.displayName,
      },
      meta: {
        migratedFrom: 'v1',
        originalData: legacySession.customData,
      },
    };
  }
}
```

## Migration from Other Auth Systems

### From Auth.js (NextAuth.js)

#### Configuration Mapping

```typescript
// NextAuth configuration
const authOptions = {
  providers: [
    SAMLProvider({
      id: "stanford-saml",
      name: "Stanford SAML",
      server: {
        loginUrl: "https://adapt-sso.stanford.edu/api/sso/login",
        // ...
      },
      // ...
    }),
  ],
  // ...
};

// ADAPT Auth equivalent
const auth = createAdaptNext({
  saml: {
    issuer: 'your-entity-id',
    idpCert: 'your-certificate',
    returnToOrigin: 'https://your-app.com',
    serviceProviderLoginUrl: 'https://adapt-sso.stanford.edu/api/sso/login',
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.NEXTAUTH_SECRET,
  },
  callbacks: {
    mapProfile: async (profile) => ({
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
    }),
  },
});
```

#### Session Access Migration

```typescript
// NextAuth
import { getServerSession } from "next-auth";

const session = await getServerSession(authOptions);

// ADAPT Auth
import { auth } from '@/lib/auth';

const session = await auth.getSession(request);
```

### From Passport.js

#### Strategy Migration

```typescript
// Passport SAML strategy
passport.use(new SAMLStrategy({
  entryPoint: 'https://adapt-sso.stanford.edu/api/sso/login',
  issuer: 'your-entity-id',
  cert: 'your-certificate',
  // ...
}, (profile, done) => {
  const user = {
    id: profile.encodedSUID,
    email: profile.userName + '@stanford.edu',
    name: profile.firstName + ' ' + profile.lastName,
  };
  return done(null, user);
}));

// ADAPT Auth equivalent
const auth = createAdaptNext({
  saml: {
    issuer: 'your-entity-id',
    idpCert: 'your-certificate',
    returnToOrigin: 'https://your-app.com',
    serviceProviderLoginUrl: 'https://adapt-sso.stanford.edu/api/sso/login',
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.SESSION_SECRET,
  },
  callbacks: {
    mapProfile: async (profile) => ({
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
    }),
  },
});
```

### From Express Session + SAML

#### Route Migration

```typescript
// Express with passport-saml
app.get('/auth/login', passport.authenticate('saml'));

app.post('/auth/acs',
  passport.authenticate('saml', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

// ADAPT Auth equivalent
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
    res.redirect('/login?error=auth_failed');
  }
});
```

## Common Migration Issues

### 1. Session Size Limitations

**Issue**: v2.0 uses cookie-only sessions which have size limits.

**Solution**: Store minimal data in sessions, use IDs for lookups.

```typescript
// Avoid: Storing large objects
session.meta = {
  fullUserProfile: { /* large object */ },
  permissions: [ /* long array */ ],
};

// Prefer: Store references
session.meta = {
  userId: user.id,
  roleIds: user.roles.map(r => r.id),
};
```

### 2. Synchronous to Asynchronous API

**Issue**: v2.0 APIs are fully asynchronous.

**Solution**: Add `await` to all auth operations.

```typescript
// v1.x (synchronous)
const user = auth.getUser(req);

// v2.0 (asynchronous)
const session = await auth.getSession(request);
const user = session?.user;
```

### 3. Framework-Specific Adapters

**Issue**: Different frameworks require different cookie stores.

**Solution**: Use appropriate cookie store for your framework.

```typescript
// Next.js
const cookieStore = createNextCookieStore(request, response);

// Express
const cookieStore = createExpressCookieStore(req, res);

// Generic Web API
const cookieStore = createWebCookieStore(request, response);
```

## Testing Migration

### Migration Test Suite

```typescript
// test-migration.ts
describe('Migration from v1.x', () => {
  it('should handle v1 configuration format', () => {
    const v1Config = {
      entityId: 'test-entity',
      certificate: 'test-cert',
      sessionSecret: 'test-secret',
    };

    const v2Config = migrateV1Config(v1Config);

    expect(v2Config.saml.issuer).toBe(v1Config.entityId);
    expect(v2Config.saml.idpCert).toBe(v1Config.certificate);
    expect(v2Config.session.secret).toBe(v1Config.sessionSecret);
  });

  it('should maintain session compatibility', async () => {
    // Test that user sessions remain valid after migration
    const legacySession = createLegacySession();
    const migratedSession = await migrateSession(legacySession);

    expect(migratedSession.user.id).toBe(legacySession.userId);
  });
});
```

## Post-Migration Checklist

- [ ] All route handlers updated to use new API
- [ ] Session access patterns updated to be async
- [ ] Configuration migrated to new format
- [ ] Tests updated for new APIs
- [ ] Environment variables updated
- [ ] Error handling updated for new error types
- [ ] Logging updated for new log format
- [ ] Security review completed
- [ ] Performance testing with cookie sessions
- [ ] Documentation updated

## Getting Help

If you encounter issues during migration:

1. Check the [troubleshooting guide](./troubleshooting.md)
2. Review the [API reference](./api-reference.md)
3. Open an issue on GitHub with migration details
4. Join the community discussions

The migration to v2.0 provides significant improvements in security, developer experience, and framework compatibility. While there are breaking changes, the new architecture provides a solid foundation for modern authentication needs.

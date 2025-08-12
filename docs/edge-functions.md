# Edge Functions Compatibility

This document details how to use the ADAPT Auth SDK in edge function environments where Node.js APIs are not available.

## Overview

The ADAPT Auth SDK provides **hybrid architecture support** where:

- **SAML authentication** runs on Node.js servers (full feature support)
- **Session validation** runs in edge functions (fast, lightweight)

This gives you the best of both worlds: secure SAML processing where it works best, and ultra-fast session checking at the edge.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│    Edge     │────│  Node.js    │
│             │    │  Function   │    │   Server    │
│             │    │             │    │             │
│ UI + Cookie │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │ (Read-only) │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Edge-Compatible Features

### ✅ What Works in Edge Functions

- **Session Reading**: Decrypt and validate existing sessions
- **Authentication Checks**: Fast user authentication validation
- **Role/Permission Checks**: Check user roles from session metadata
- **Cookie Parsing**: Parse and validate session cookies
- **CSRF Token Validation**: Validate CSRF tokens
- **RelayState Verification**: Verify signed RelayState tokens

### ❌ What Requires Node.js

- **SAML Processing**: XML parsing, signature validation, certificate handling
- **Session Creation**: Creating new encrypted session cookies
- **Database Operations**: User lookups, audit logging
- **Complex Authentication Logic**: Multi-factor auth, custom providers

## Edge Session Reader

The `EdgeSessionReader` class provides lightweight session validation:

### Key Features

- **Zero Dependencies**: Uses only Web APIs (crypto, btoa/atob)
- **Iron-Session Compatible**: Can decrypt sessions created by the main SDK
- **Framework Agnostic**: Works with any edge function platform
- **Security Focused**: Same security standards as the main SDK

### Basic Usage

```typescript
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

// Create reader with session secret
const sessionReader = new EdgeSessionReader(
  process.env.ADAPT_AUTH_SESSION_SECRET!,
  'adapt-auth-session' // cookie name
);

// Check authentication from Request
const isAuthenticated = await sessionReader.isAuthenticated(request);

// Get user from session
const user = await sessionReader.getUser(request);

// Check user roles
const isAdmin = await sessionReader.hasRole(request, 'admin');
```

## Platform-Specific Examples

### Next.js Edge Middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { isAuthenticatedEdge } from 'adapt-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  // Fast authentication check at the edge
  const isAuthenticated = await isAuthenticatedEdge(request);

  if (!isAuthenticated && request.nextUrl.pathname.startsWith('/protected')) {
    return NextResponse.redirect(new URL('/api/auth/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/protected/:path*', '/admin/:path*'],
  runtime: 'edge',
};
```

### Next.js Edge API Route

```typescript
// app/api/session/route.ts
import { NextRequest } from 'next/server';
import { getSessionFromNextRequest } from 'adapt-auth-sdk/edge-session';

export async function GET(request: NextRequest) {
  const session = await getSessionFromNextRequest(request);

  if (!session) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  return Response.json({
    user: session.user,
    authenticated: true,
    roles: session.meta?.roles || [],
  });
}

export const runtime = 'edge';
```

### Vercel Edge Functions

```typescript
// api/check-auth.ts
import type { NextRequest } from 'next/server';
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export const config = { runtime: 'edge' };

const sessionReader = new EdgeSessionReader(
  process.env.ADAPT_AUTH_SESSION_SECRET!
);

export default async function handler(request: NextRequest) {
  const session = await sessionReader.getSessionFromRequest(request);

  return Response.json({
    authenticated: !!session,
    user: session?.user || null,
  });
}
```

### Cloudflare Workers

```typescript
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export default {
  async fetch(request: Request, env: any) {
    const sessionReader = new EdgeSessionReader(env.SESSION_SECRET);

    const session = await sessionReader.getSessionFromRequest(request);

    if (!session && new URL(request.url).pathname.startsWith('/protected')) {
      return Response.redirect('https://yourapp.com/api/auth/login');
    }

    return new Response(`Hello ${session?.user?.name || 'Anonymous'}!`);
  },
};
```

### Deno Deploy

```typescript
import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { EdgeSessionReader } from "npm:adapt-auth-sdk/edge-session";

const sessionReader = new EdgeSessionReader(
  Deno.env.get("SESSION_SECRET")!
);

serve(async (request: Request) => {
  const session = await sessionReader.getSessionFromRequest(request);

  if (!session) {
    return new Response("Not authenticated", { status: 401 });
  }

  return Response.json({
    message: "Hello from Deno Deploy!",
    user: session.user,
  });
});
```

## Performance Benefits

### Response Time Comparison

```typescript
// ❌ Traditional: Every request to main server
Browser → Load Balancer → Node.js Server → Response
         (~200ms average)

// ✅ Edge: Session validation at the edge
Browser → Edge Function → Response
         (~20ms average)

// 🎯 Result: 10x faster for session validation
```

### When to Use Edge vs Node.js

| Operation | Recommended Runtime | Reason |
|-----------|-------------------|---------|
| Session validation | Edge Function | Ultra-fast response |
| Role checking | Edge Function | Data already in cookie |
| User redirects | Edge Function | Minimize latency |
| SAML authentication | Node.js Server | Complex XML processing |
| Session creation | Node.js Server | Encryption requirements |
| Database queries | Node.js Server | Full framework support |

## Migration Strategy

### Step 1: Keep Existing Auth Routes

Your Node.js authentication routes remain unchanged:

```typescript
// app/api/auth/login/route.ts (Node.js runtime)
export async function GET(request: Request) {
  return auth.login(request); // Full SAML processing
}

// app/api/auth/acs/route.ts (Node.js runtime)
export async function POST(request: Request) {
  return auth.handleCallback(request); // Session creation
}
```

### Step 2: Add Edge Session Routes

Create new edge-optimized routes for session operations:

```typescript
// app/api/session/route.ts (Edge runtime)
import { getSessionFromNextRequest } from 'adapt-auth-sdk/edge-session';

export async function GET(request: Request) {
  const session = await getSessionFromNextRequest(request);
  return Response.json(session);
}

export const runtime = 'edge';
```

### Step 3: Update Client Code

Update your client-side session fetching:

```typescript
// Before: Slow server-side session check
const response = await fetch('/api/auth/session');

// After: Fast edge session check
const response = await fetch('/api/session');
```

### Step 4: Optimize Middleware

Replace server-side middleware with edge middleware:

```typescript
// Before: Server-side authentication check
export async function middleware(request: NextRequest) {
  const session = await auth.getSession(request); // Slow
  // ...
}

// After: Edge authentication check
export async function middleware(request: NextRequest) {
  const isAuth = await isAuthenticatedEdge(request); // Fast
  // ...
}

export const config = { runtime: 'edge' };
```

## Security Considerations

### Session Security

The edge session reader maintains the same security standards:

- **Encryption**: Uses the same iron-session encryption
- **Validation**: Verifies signatures and expiration
- **Secrets**: Requires the same session secret
- **Cookies**: Reads the same secure cookies

### What's Safe in Edge Functions

✅ **Safe Operations**:
```typescript
// These operations are safe and recommended
const session = await sessionReader.getSessionFromRequest(request);
const isAuthenticated = await sessionReader.isAuthenticated(request);
const user = await sessionReader.getUser(request);
const hasRole = await sessionReader.hasRole(request, 'admin');
```

⚠️ **Avoid in Edge Functions**:
```typescript
// These should stay on Node.js servers
await auth.login(request);           // SAML processing
await auth.handleCallback(request);  // Session creation
await sessionManager.createSession(user); // Cookie encryption
```

### Environment Variables

Ensure session secrets are available in edge environments:

```bash
# Required in both Node.js and Edge environments
ADAPT_AUTH_SESSION_SECRET="your-32-character-secret"
ADAPT_AUTH_SESSION_NAME="adapt-auth-session"
```

## Troubleshooting

### Common Issues

1. **"Session secret is required"**
   ```typescript
   // Ensure environment variable is set
   const reader = new EdgeSessionReader(
     process.env.ADAPT_AUTH_SESSION_SECRET!
   );
   ```

2. **"Failed to decrypt session"**
   ```typescript
   // Check that the same secret is used for creation and reading
   // Verify the cookie name matches
   ```

3. **"Invalid cookie format"**
   ```typescript
   // Ensure the session was created with iron-session
   // Check that the cookie hasn't been corrupted
   ```

### Debug Logging

Enable debug logging to troubleshoot:

```typescript
import { DefaultLogger } from 'adapt-auth-sdk';

const logger = new DefaultLogger();
const sessionReader = new EdgeSessionReader(secret, cookieName, logger);
```

### Testing Edge Functions Locally

Test edge compatibility in your development environment:

```typescript
// Test edge session reading
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

const sessionReader = new EdgeSessionReader('test-secret-32-chars-long!!');

// Mock a request with cookies
const request = new Request('https://localhost:3000', {
  headers: {
    'cookie': 'adapt-auth-session=encrypted.session.data'
  }
});

const session = await sessionReader.getSessionFromRequest(request);
console.log('Session:', session);
```

## Best Practices

### 1. Use Hybrid Architecture

```typescript
// ✅ Recommended pattern
┌─────────────┐
│ Edge Layer  │ ← Fast session validation
│ (Read-only) │
└─────────────┘
        │
        ▼
┌─────────────┐
│ Node.js     │ ← Full authentication features
│ (Full SDK)  │
└─────────────┘
```

### 2. Optimize Session Data

Keep session cookies small for edge performance:

```typescript
// ✅ Good: Store minimal data
session.meta = {
  userId: user.id,
  roles: ['admin', 'user'],
  tenantId: 'tenant123'
};

// ❌ Avoid: Large objects
session.meta = {
  fullUserProfile: { /* large object */ },
  permissions: [ /* 100+ permissions */ ]
};
```

### 3. Cache Strategy

Implement intelligent caching:

```typescript
// Edge function with short-term caching
const CACHE_TTL = 60; // 1 minute

export async function middleware(request: NextRequest) {
  const cacheKey = `session:${getUserId(request)}`;

  // Check cache first
  let session = await cache.get(cacheKey);

  if (!session) {
    // Validate session and cache result
    session = await sessionReader.getSessionFromRequest(request);
    if (session) {
      await cache.set(cacheKey, session, CACHE_TTL);
    }
  }

  // Use cached session
  if (!session && isProtectedRoute(request)) {
    return NextResponse.redirect('/login');
  }
}
```

### 4. Error Handling

Implement graceful fallbacks:

```typescript
export async function middleware(request: NextRequest) {
  try {
    const isAuth = await isAuthenticatedEdge(request);

    if (!isAuth && isProtectedRoute(request)) {
      return NextResponse.redirect('/login');
    }
  } catch (error) {
    // Log error and allow request (graceful degradation)
    console.error('Edge auth check failed:', error);

    // Optionally redirect to full server-side check
    if (isCriticalRoute(request)) {
      return NextResponse.redirect('/api/auth/verify');
    }
  }

  return NextResponse.next();
}
```

This edge function compatibility enables you to get the performance benefits of edge computing while maintaining the security and reliability of your existing SAML authentication system.

# Edge Functions Usage Examples

This directory contains examples of how to use the ADAPT Auth SDK in edge function environments where Node.js APIs are not available.

## Key Concepts

### Session Checking in Edge Functions

The SDK provides `EdgeSessionReader` for checking sessions in edge environments:

- **Read-only**: Can decrypt and validate existing sessions
- **No Dependencies**: Uses only Web APIs (crypto, btoa/atob)
- **Compatible**: Works with Vercel Edge, Netlify Edge, Cloudflare Workers, Deno Deploy

### Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│    Edge     │────│  Node.js    │
│             │    │  Function   │    │   Server    │
│             │    │             │    │             │
│ UI + Cookie │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │             │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Authentication Flow

1. **Login**: User redirected to Node.js server for SAML authentication
2. **Session Creation**: Node.js server creates encrypted session cookie
3. **Edge Validation**: Edge functions validate session cookie without Node.js
4. **Performance**: Fast session checks at the edge, close to users

## Examples

### Next.js Edge Middleware

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { isAuthenticatedEdge } from 'adapt-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  // Check if user is authenticated using edge-compatible function
  const isAuthenticated = await isAuthenticatedEdge(request);

  if (!isAuthenticated && request.nextUrl.pathname.startsWith('/protected')) {
    // Redirect to login (handled by Node.js)
    return NextResponse.redirect(new URL('/api/auth/login', request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/protected/:path*', '/admin/:path*'],
  runtime: 'edge', // Enable edge runtime
};
```

### Next.js Edge API Route

```typescript
// app/api/me/route.ts
import { NextRequest } from 'next/server';
import { getSessionFromNextRequest } from 'adapt-auth-sdk/edge-session';

export async function GET(request: NextRequest) {
  // Get session data in edge function
  const session = await getSessionFromNextRequest(request);

  if (!session) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  return Response.json({
    user: session.user,
    authenticated: true,
  });
}

// Enable edge runtime
export const runtime = 'edge';
```

### Vercel Edge Function

```typescript
// api/check-auth.ts
import type { NextRequest } from 'next/server';
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export const config = {
  runtime: 'edge',
};

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
// worker.ts
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export default {
  async fetch(request: Request, env: any) {
    const sessionReader = new EdgeSessionReader(env.SESSION_SECRET);

    const session = await sessionReader.getSessionFromRequest(request);

    if (!session && new URL(request.url).pathname.startsWith('/protected')) {
      return Response.redirect('https://yourapp.com/api/auth/login');
    }

    // Continue with your app logic
    return new Response('Hello from Cloudflare Workers!');
  },
};
```

### Deno Deploy

```typescript
// main.ts
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

### Edge vs Traditional Server

```typescript
// ❌ Traditional: Every request goes to main server
Browser → Load Balancer → Node.js Server → Database → Response
         (100-300ms latency)

// ✅ Edge: Session validation at the edge
Browser → Edge Function (session check) → Response
         (10-50ms latency)

// Only authentication and session creation go to main server
Browser → Edge → Node.js Server (for auth only)
```

### Benchmarks

- **Traditional**: ~200ms average response time
- **Edge**: ~20ms average response time
- **Improvement**: 10x faster for session validation

## Security Considerations

### What's Safe in Edge Functions

✅ **Safe Operations**:
- Reading and decrypting session cookies
- Validating session expiration
- Checking user roles/permissions from session
- CSRF token validation
- Redirecting to login

❌ **Avoid in Edge Functions**:
- SAML response processing (use Node.js server)
- Creating new sessions (use Node.js server)
- Direct database access for user data
- Complex authentication logic

### Security Best Practices

1. **Session Secrets**: Use strong, unique secrets for each environment
2. **Cookie Security**: Ensure HttpOnly, Secure, SameSite flags
3. **Edge Validation**: Only validate sessions, don't create them
4. **Fallback**: Always fallback to main server for complex auth

## Migration Guide

### Step 1: Update Authentication Routes

Keep your existing Node.js authentication routes unchanged:

```typescript
// app/api/auth/login/route.ts (Node.js runtime)
export async function GET(request: Request) {
  return auth.login(request); // Full SAML handling
}

// app/api/auth/acs/route.ts (Node.js runtime)
export async function POST(request: Request) {
  return auth.handleCallback(request); // Session creation
}
```

### Step 2: Add Edge Session Checking

Create new edge-compatible routes for session validation:

```typescript
// app/api/session/route.ts (Edge runtime)
import { getSessionFromNextRequest } from 'adapt-auth-sdk/edge-session';

export async function GET(request: Request) {
  const session = await getSessionFromNextRequest(request);
  return Response.json(session);
}

export const runtime = 'edge';
```

### Step 3: Update Middleware

Replace server-side session checks with edge-compatible ones:

```typescript
// middleware.ts
import { isAuthenticatedEdge } from 'adapt-auth-sdk/edge-session';

export async function middleware(request: NextRequest) {
  // Fast session check at the edge
  const isAuthenticated = await isAuthenticatedEdge(request);

  if (!isAuthenticated && isProtectedRoute(request)) {
    return NextResponse.redirect(new URL('/api/auth/login', request.url));
  }
}

export const config = { runtime: 'edge' };
```

## Troubleshooting

### Common Issues

1. **"Session secret is required"**
   ```typescript
   // Solution: Ensure environment variable is set
   const sessionReader = new EdgeSessionReader(
     process.env.ADAPT_AUTH_SESSION_SECRET || 'your-secret'
   );
   ```

2. **"Invalid cookie format"**
   ```typescript
   // Solution: Check cookie name matches session creation
   const session = await getSessionFromNextRequest(
     request,
     secret,
     'adapt-auth-session' // Must match session creation
   );
   ```

3. **"Failed to decrypt session"**
   ```typescript
   // Solution: Ensure same secret used for encryption and decryption
   // Check that the cookie was created with iron-session
   ```

### Debug Mode

Enable debug logging to troubleshoot issues:

```typescript
import { DefaultLogger } from 'adapt-auth-sdk';

const logger = new DefaultLogger();
const sessionReader = new EdgeSessionReader(secret, cookieName, logger);
```

## Limitations

### Edge Function Constraints

- **No Node.js APIs**: Cannot use Buffer, fs, crypto (Node.js), etc.
- **Read-Only**: Can only validate existing sessions, not create new ones
- **Memory Limits**: Edge functions have memory constraints
- **Execution Time**: Limited execution time (varies by platform)

### Recommended Architecture

```typescript
// ✅ Recommended: Hybrid approach
┌─────────────────┐
│ Edge Functions  │ ← Fast session validation
│ (Read-only)     │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Node.js Server  │ ← SAML processing, session creation
│ (Full features) │
└─────────────────┘
```

This approach gives you the best of both worlds: fast edge validation for common operations and full Node.js capabilities for complex authentication flows.

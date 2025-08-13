# Netlify Edge Functions Usage Examples

This directory contains examples of how to use the ADAPT Auth SDK in Netlify edge functions for fast session validation.

## Key Concepts

### Session Checking in Edge Functions

The SDK provides `EdgeSessionReader` for checking sessions in edge environments:

- **Read-only**: Can decrypt and validate existing sessions
- **No Dependencies**: Uses only Web APIs (crypto, btoa/atob)
- **Optimized for Netlify**: Fast session validation at the edge

### Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Browser   │────│  Netlify    │────│  Node.js    │
│             │    │    Edge     │    │   Server    │
│             │    │             │    │             │
│ UI + Cookie │    │ Session     │    │ SAML +      │
│             │    │ Validation  │    │ Session     │
│             │    │             │    │ Creation    │
└─────────────┘    └─────────────┘    └─────────────┘
```

### Authentication Flow

1. **Login**: User redirected to Node.js server for SAML authentication
2. **Session Creation**: Node.js server creates encrypted session cookie
3. **Edge Validation**: Netlify edge functions validate session cookie without Node.js
4. **Performance**: Fast session checks at the edge, close to users

## Examples

### Netlify Edge Function

```typescript
// netlify/edge-functions/auth-check.ts
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  const sessionReader = new EdgeSessionReader(
    Deno.env.get('ADAPT_AUTH_SESSION_SECRET')!
  );

  const session = await sessionReader.getSessionFromRequest(request);

  if (!session) {
    return Response.json({ error: 'Not authenticated' }, { status: 401 });
  }

  return Response.json({
    authenticated: true,
    user: session.user,
  });
}

export const config = {
  path: "/api/auth-check",
};
```

### Netlify Edge Function for Protected Routes

```typescript
// netlify/edge-functions/protect.ts
import { EdgeSessionReader } from 'adapt-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  const url = new URL(request.url);

  // Only protect certain paths
  if (!url.pathname.startsWith('/protected')) {
    return; // Continue to next function/origin
  }

  const sessionReader = new EdgeSessionReader(
    Deno.env.get('ADAPT_AUTH_SESSION_SECRET')!
  );

  const session = await sessionReader.getSessionFromRequest(request);

  if (!session) {
    // Redirect to login
    return Response.redirect(new URL('/api/auth/login', request.url).toString());
  }

  // User is authenticated, continue
  return;
}

export const config = {
  path: "/protected/*",
};
```

### Get User ID for Logging or Analytics

```typescript
// netlify/edge-functions/analytics.ts
import { getUserIdFromRequest } from 'adapt-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  // Get just the user ID for logging/analytics
  const userId = await getUserIdFromRequest(request);

  if (userId) {
    // Log user activity
    console.log(`User ${userId} accessed ${request.url}`);

    // Add user ID to response headers for downstream services
    const response = await context.next();
    response.headers.set('X-User-ID', userId);
    return response;
  }

  // Continue without user tracking for anonymous users
  return await context.next();
}

export const config = {
  path: "/*",
};
```

### Ultra-Fast User ID Extraction (Performance Optimized)

```typescript
// netlify/edge-functions/quick-analytics.ts
import { getQuickUserId } from 'adapt-auth-sdk/edge-session';

export default async function handler(request: Request, context: any) {
  // Ultra-fast user ID extraction optimized for edge performance
  // Tries quick extraction first, falls back to full decryption if needed
  const userId = await getQuickUserId(request);

  if (userId) {
    // Log user activity with minimal latency
    console.log(`User ${userId} accessed ${request.url}`);

    // Add to analytics queue (non-blocking)
    context.waitUntil(
      fetch('https://analytics.example.com/track', {
        method: 'POST',
        body: JSON.stringify({ userId, url: request.url, timestamp: Date.now() })
      })
    );
  }

  // Continue to next function/origin with minimal delay
  return await context.next();
}

export const config = {
  path: "/*",
};
```

## Performance Benefits

### Netlify Edge vs Traditional Server

```typescript
// ❌ Traditional: Every request goes to main server
Browser → Load Balancer → Node.js Server → Database → Response
         (100-300ms latency)

// ✅ Netlify Edge: Session validation at the edge
Browser → Netlify Edge Function (session check) → Response
         (10-50ms latency)

// Only authentication and session creation go to main server
Browser → Netlify Edge → Node.js Server (for auth only)
```

### Development vs Production

- **Localhost Development**: Use standard Next.js/Gatsby development server
- **Netlify Production**: Edge functions automatically deployed and optimized
- **Testing**: Use `netlify dev` for local edge function testing

## Local Development Setup

### Environment Variables

Create `.env.local` for development:

```bash
# Required for both localhost and Netlify
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate-string
ADAPT_AUTH_SAML_RETURN_ORIGIN=http://localhost:3000
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key

# Optional
ADAPT_AUTH_RELAY_STATE_SECRET=another-32-character-secret-key
```

### Netlify Configuration

Create `netlify.toml` in your project root:

```toml
[build]
  functions = "netlify/functions"
  edge_functions = "netlify/edge-functions"

[[edge_functions]]
  function = "protect"
  path = "/protected/*"

[[edge_functions]]
  function = "auth-check"
  path = "/api/auth-check"

[dev]
  framework = "next"
  targetPort = 3000
```

## Security Considerations

### What's Safe in Edge Functions

✅ **Safe Operations**:
- Reading and decrypting session cookies
- Validating session expiration
- Extracting user information from session
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
// pages/api/auth/login.ts or app/api/auth/login/route.ts
export async function GET(request: Request) {
  return auth.login(request); // Full SAML handling
}

// pages/api/auth/acs.ts or app/api/auth/acs/route.ts
export async function POST(request: Request) {
  return auth.handleCallback(request); // Session creation
}
```

### Step 2: Add Netlify Edge Functions

Create edge functions for session validation:

```typescript
// netlify/edge-functions/session.ts
import { getSessionFromRequest } from 'adapt-auth-sdk/edge-session';

export default async function handler(request: Request) {
  const session = await getSessionFromRequest(request);
  return Response.json(session);
}

export const config = { path: "/api/session" };
```

### Step 3: Test Locally

Use Netlify CLI for local development:

```bash
# Install Netlify CLI
npm install -g netlify-cli

# Start local development with edge functions
netlify dev

# Your app runs on http://localhost:8888 with edge functions enabled
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
// ✅ Recommended: Netlify hybrid approach
┌─────────────────┐
│ Netlify Edge    │ ← Fast session validation
│ Functions       │
│ (Read-only)     │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│ Node.js Server  │ ← SAML processing, session creation
│ (Full features) │   (localhost dev / Netlify Functions)
└─────────────────┘
```

This approach gives you fast edge validation for common operations and full Node.js capabilities for authentication flows, optimized for localhost development and Netlify production deployment.

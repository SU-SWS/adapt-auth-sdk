# Next.js App Router - Separate Import Pattern

As of v2.0.0, the Next.js integration is available as a separate import to prevent bundling issues and improve tree-shaking. This ensures the core package doesn't depend on Next.js.

## Correct Import Pattern

### ✅ Do this (v2.0.0+)

```typescript
// lib/auth.ts
import { createAdaptNext } from 'adapt-auth-sdk/next';

export const auth = createAdaptNext({
  saml: {
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
    callbackOrigin: process.env.ADAPT_AUTH_SAML_CALLBACK_ORIGIN!
  },
  session: {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!
  }
});
```

### ❌ Don't do this (no longer supported)

```typescript
// This will no longer work in v2.0.0+
import { createAdaptNext } from 'adapt-auth-sdk'; // Next.js removed from main export
```

## Benefits of Separate Import

1. **No bundling issues**: The core package doesn't try to resolve `next/headers` in non-Next.js environments
2. **Better tree-shaking**: Only load Next.js code when explicitly needed
3. **Cleaner dependencies**: Core package doesn't depend on Next.js optionalDependencies
4. **Framework agnostic**: Other frameworks can use the core package without Next.js overhead

## Route Examples

### Login Route
```typescript
// app/login/route.ts
import { auth } from '@/lib/auth'; // Uses 'adapt-auth-sdk/next'

export async function GET() {
  return auth.login({ finalDestination: '/dashboard' });
}
```

### ACS (Callback) Route
```typescript
// app/auth/acs/route.ts  
import { auth } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const { user, finalDestination } = await auth.authenticate(request);
    return Response.redirect(finalDestination || '/dashboard');
  } catch (error) {
    console.error('Authentication failed:', error);
    return Response.redirect('/login?error=auth_failed');
  }
}
```

### Server Component
```typescript
// app/dashboard/page.tsx
import { auth } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function Dashboard() {
  const user = await auth.getUser();
  
  if (!user) {
    redirect('/login');
  }
  
  return (
    <div>
      <h1>Welcome {user.name}!</h1>
      <p>Email: {user.email}</p>
    </div>
  );
}
```

## Migration from v1.x

If you're migrating from v1.x, simply update your import:

```diff
- import { createAdaptNext } from 'adapt-auth-sdk';
+ import { createAdaptNext } from 'adapt-auth-sdk/next';
```

All other APIs remain the same.
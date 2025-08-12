# Getting Started

This guide will help you get up and running with the ADAPT Auth SDK quickly.

## Installation

```bash
npm install adapt-auth-sdk
```

## Requirements

- Node.js 18 or higher
- TypeScript 5.x (recommended)
- A Stanford WebAuth SAML entity and certificate

## Quick Start

### Next.js App Router

```typescript
// app/auth/config.ts
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
  verbose: process.env.NODE_ENV === 'development',
});

// app/api/auth/login/route.ts
import { auth } from '../../config';

export async function GET() {
  return await auth.login({ returnTo: '/dashboard' });
}

// app/api/auth/acs/route.ts
import { auth } from '../../config';

export async function POST(request: Request) {
  try {
    const { user, returnTo } = await auth.authenticate(request);
    return Response.redirect(returnTo || '/dashboard');
  } catch (error) {
    return Response.redirect('/login?error=auth_failed');
  }
}

// app/api/auth/logout/route.ts
import { auth } from '../../config';

export async function POST() {
  await auth.logout();
  return Response.redirect('/');
}

// app/dashboard/page.tsx
import { auth } from '../auth/config';
import { redirect } from 'next/navigation';

export default async function Dashboard() {
  const user = await auth.getUser();

  if (!user) {
    redirect('/login');
  }

  return (
    <div>
      <h1>Welcome, {user.name}!</h1>
      <p>Email: {user.email}</p>
    </div>
  );
}
```

### Express.js

```typescript
import express from 'express';
import { SAMLProvider, SessionManager, createExpressCookieStore } from 'adapt-auth-sdk';

const app = express();
app.use(express.urlencoded({ extended: true }));

const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
});

// Login route
app.get('/auth/login', async (req, res) => {
  const loginUrl = await samlProvider.getLoginUrl({ returnTo: '/dashboard' });
  res.redirect(loginUrl);
});

// SAML callback (ACS)
app.post('/auth/acs', async (req, res) => {
  try {
    const { user, returnTo } = await samlProvider.authenticate({ req });

    const cookieStore = createExpressCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, {
      name: 'adapt-auth-session',
      secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
    });

    await sessionManager.createSession(user);
    res.redirect(returnTo || '/dashboard');
  } catch (error) {
    res.redirect('/login?error=auth_failed');
  }
});

// Protected route middleware
const requireAuth = async (req, res, next) => {
  const cookieStore = createExpressCookieStore(req, res);
  const sessionManager = new SessionManager(cookieStore, {
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  });

  const user = await sessionManager.getUser();
  if (!user) {
    return res.redirect('/login');
  }

  req.user = user;
  next();
};

app.get('/dashboard', requireAuth, (req, res) => {
  res.json({ message: `Welcome, ${req.user.name}!` });
});

app.listen(3000);
```

## Next Steps

- [Configure your environment](./configuration.md)
- [Learn about security features](./security.md)
- [Explore advanced usage patterns](./advanced-usage.md)
- [Check the API reference](./api-reference.md)

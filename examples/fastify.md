# Fastify Example

This example shows how to integrate ADAPT Auth SDK with Fastify, a fast and low overhead web framework for Node.js.

## Setup

### 1. Install Dependencies

```bash
npm install fastify @fastify/cookie @fastify/session adapt-auth-sdk
npm install -D @types/node
```

### 2. Environment Variables

```bash
# .env
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate-string
ADAPT_AUTH_SAML_RETURN_ORIGIN=https://your-app.com
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key-here-min
ADAPT_AUTH_RELAY_STATE_SECRET=another-32-character-secret-key-min
PORT=3000
```

### 3. Configuration

```typescript
// src/auth.ts
import { SAMLProvider, SessionManager } from 'adapt-auth-sdk';

export const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
  relayStateSecret: process.env.ADAPT_AUTH_RELAY_STATE_SECRET,
});

export const sessionManager = new SessionManager({
  name: 'adapt-auth-session',
  secret: process.env.ADAPT_AUTH_SESSION_SECRET!,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 7, // 1 week
  },
});
```

## Fastify Application

### Main Application

```typescript
// src/server.ts
import Fastify from 'fastify';
import { samlProvider, sessionManager } from './auth';

const fastify = Fastify({
  logger: process.env.NODE_ENV !== 'production',
});

// Register plugins
await fastify.register(import('@fastify/cookie'));
await fastify.register(import('@fastify/formbody'));

// Declare session interface
declare module 'fastify' {
  interface FastifyRequest {
    session?: {
      user: any;
      meta?: Record<string, unknown>;
      issuedAt: number;
      expiresAt: number;
    };
    user?: any;
  }
}

// Authentication hook
fastify.addHook('preHandler', async (request, reply) => {
  // Skip auth for public routes
  const publicRoutes = ['/', '/health', '/auth/login', '/auth/acs'];
  if (publicRoutes.includes(request.url)) {
    return;
  }

  try {
    const session = await sessionManager.getSession(request, reply);
    request.session = session;
    request.user = session?.user;
  } catch (error) {
    fastify.log.error('Session error:', error);
  }
});

// Authentication middleware
const requireAuth = async (request: any, reply: any) => {
  if (!request.session) {
    if (request.url.startsWith('/api/')) {
      reply.code(401).send({ error: 'Authentication required' });
      return;
    } else {
      reply.redirect(`/auth/login?returnTo=${encodeURIComponent(request.url)}`);
      return;
    }
  }
};

// Auth routes
fastify.get('/auth/login', async (request, reply) => {
  try {
    const { returnTo } = request.query as { returnTo?: string };
    const { url } = await samlProvider.getLoginUrl(request, { returnTo });
    reply.redirect(url);
  } catch (error) {
    fastify.log.error('Login error:', error);
    reply.code(500).send('Login failed');
  }
});

fastify.post('/auth/acs', async (request, reply) => {
  try {
    const profile = await samlProvider.handleCallback(request);

    // Create session
    await sessionManager.createSession(request, reply, {
      user: {
        id: profile.nameID,
        email: profile.email || profile.mail,
        name: profile.displayName || `${profile.givenName} ${profile.sn}`,
        imageUrl: profile.picture,
      },
      meta: {
        loginTime: new Date().toISOString(),
        userAgent: request.headers['user-agent'],
      },
    });

    // Redirect to return URL or home
    const returnTo = (request.body as any).RelayState || '/dashboard';
    reply.redirect(returnTo);
  } catch (error) {
    fastify.log.error('Callback error:', error);
    reply.code(400).send('Authentication failed');
  }
});

fastify.post('/auth/logout', { preHandler: requireAuth }, async (request, reply) => {
  try {
    await sessionManager.destroySession(request, reply);
    reply.redirect('/');
  } catch (error) {
    fastify.log.error('Logout error:', error);
    reply.code(500).send('Logout failed');
  }
});

// Protected routes
fastify.get('/dashboard', { preHandler: requireAuth }, async (request, reply) => {
  reply.type('text/html').send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .btn { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>Dashboard</h1>
        <div class="card">
            <h2>Welcome, ${request.user?.name || request.user?.email}!</h2>
            <p>User ID: ${request.user?.id}</p>
            <a href="/profile" class="btn">View Profile</a>
            <a href="/api/me" class="btn">API Data</a>
            <form method="post" action="/auth/logout" style="display: inline;">
                <button type="submit" class="btn" style="background: #dc3545;">Logout</button>
            </form>
        </div>
    </body>
    </html>
  `);
});

fastify.get('/profile', { preHandler: requireAuth }, async (request, reply) => {
  reply.type('text/html').send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profile</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .card { border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin: 20px 0; }
            .btn { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow: auto; }
        </style>
    </head>
    <body>
        <h1>User Profile</h1>
        <div class="card">
            <h2>User Information</h2>
            <pre>${JSON.stringify(request.user, null, 2)}</pre>
        </div>
        <div class="card">
            <h2>Session Metadata</h2>
            <pre>${JSON.stringify(request.session?.meta, null, 2)}</pre>
        </div>
        <a href="/dashboard" class="btn">Back to Dashboard</a>
    </body>
    </html>
  `);
});

// API routes
fastify.get('/api/me', { preHandler: requireAuth }, async (request, reply) => {
  reply.send({
    user: request.user,
    meta: request.session?.meta,
    issuedAt: request.session?.issuedAt,
    expiresAt: request.session?.expiresAt,
  });
});

fastify.get('/api/session', async (request, reply) => {
  if (!request.session) {
    reply.send({ authenticated: false });
  } else {
    reply.send({
      authenticated: true,
      user: request.user,
    });
  }
});

// Public routes
fastify.get('/', async (request, reply) => {
  const isAuthenticated = !!request.session;

  reply.type('text/html').send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fastify Auth Example</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; text-align: center; }
            .card { border: 1px solid #ddd; padding: 40px; border-radius: 8px; max-width: 400px; margin: 0 auto; }
            .btn { background: #007cba; color: white; padding: 15px 30px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 10px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Fastify Auth Demo</h1>
            ${isAuthenticated
              ? `<p>Welcome back, ${request.user?.name || request.user?.email}!</p>
                 <a href="/dashboard" class="btn">Go to Dashboard</a>
                 <form method="post" action="/auth/logout" style="display: inline;">
                   <button type="submit" class="btn" style="background: #dc3545;">Logout</button>
                 </form>`
              : `<p>Please sign in to continue</p>
                 <a href="/auth/login" class="btn">Sign In with Stanford</a>`
            }
        </div>
    </body>
    </html>
  `);
});

fastify.get('/health', async (request, reply) => {
  reply.send({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Error handler
fastify.setErrorHandler((error, request, reply) => {
  fastify.log.error(error);

  if (request.url.startsWith('/api/')) {
    reply.code(500).send({ error: 'Internal server error' });
  } else {
    reply.code(500).type('text/html').send(`
      <h1>Error 500</h1>
      <p>Something went wrong. Please try again later.</p>
      <a href="/">Go Home</a>
    `);
  }
});

// Start server
const start = async () => {
  try {
    const port = parseInt(process.env.PORT || '3000', 10);
    await fastify.listen({ port, host: '0.0.0.0' });
    console.log(`Server running at http://localhost:${port}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();

export default fastify;
```

## Plugins and Hooks

### Authentication Plugin

```typescript
// src/plugins/auth.ts
import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';
import { sessionManager } from '../auth';

export default fp(async function (fastify: FastifyInstance) {
  // Decorate request with auth helpers
  fastify.decorateRequest('isAuthenticated', function () {
    return !!this.session;
  });

  fastify.decorateRequest('requireRole', function (role: string) {
    if (!this.session) {
      throw new Error('Not authenticated');
    }

    const userRoles = this.session.meta?.roles as string[] || [];
    if (!userRoles.includes(role)) {
      throw new Error(`Missing required role: ${role}`);
    }

    return true;
  });

  // Add session hook
  fastify.addHook('preHandler', async (request, reply) => {
    try {
      const session = await sessionManager.getSession(request, reply);
      request.session = session;
      request.user = session?.user;
    } catch (error) {
      fastify.log.error('Session hook error:', error);
    }
  });
});

declare module 'fastify' {
  interface FastifyRequest {
    isAuthenticated(): boolean;
    requireRole(role: string): boolean;
  }
}
```

### Rate Limiting for Auth Routes

```typescript
// src/plugins/rateLimiting.ts
import fp from 'fastify-plugin';
import { FastifyInstance } from 'fastify';

export default fp(async function (fastify: FastifyInstance) {
  await fastify.register(import('@fastify/rate-limit'), {
    max: 5, // 5 requests
    timeWindow: '1 minute', // per minute
    skipOnError: false,
    addHeaders: {
      'x-ratelimit-limit': true,
      'x-ratelimit-remaining': true,
      'x-ratelimit-reset': true
    }
  });
});
```

## Route Organization

### Auth Routes Plugin

```typescript
// src/routes/auth.ts
import { FastifyInstance } from 'fastify';
import { samlProvider, sessionManager } from '../auth';

export default async function authRoutes(fastify: FastifyInstance) {
  fastify.get('/login', async (request, reply) => {
    try {
      const { returnTo } = request.query as { returnTo?: string };
      const { url } = await samlProvider.getLoginUrl(request, { returnTo });
      reply.redirect(url);
    } catch (error) {
      fastify.log.error('Login error:', error);
      reply.code(500).send('Login failed');
    }
  });

  fastify.post('/acs', async (request, reply) => {
    try {
      const profile = await samlProvider.handleCallback(request);

      await sessionManager.createSession(request, reply, {
        user: {
          id: profile.nameID,
          email: profile.email || profile.mail,
          name: profile.displayName || `${profile.givenName} ${profile.sn}`,
        },
        meta: {
          loginTime: new Date().toISOString(),
          ip: request.ip,
        },
      });

      const returnTo = (request.body as any).RelayState || '/dashboard';
      reply.redirect(returnTo);
    } catch (error) {
      fastify.log.error('Callback error:', error);
      reply.code(400).send('Authentication failed');
    }
  });

  fastify.post('/logout', {
    preHandler: async (request, reply) => {
      if (!request.session) {
        reply.code(401).send({ error: 'Not authenticated' });
      }
    }
  }, async (request, reply) => {
    try {
      await sessionManager.destroySession(request, reply);

      if (request.headers.accept?.includes('application/json')) {
        reply.send({ success: true });
      } else {
        reply.redirect('/');
      }
    } catch (error) {
      fastify.log.error('Logout error:', error);
      reply.code(500).send('Logout failed');
    }
  });

  fastify.get('/session', async (request, reply) => {
    if (!request.session) {
      reply.send({ authenticated: false });
    } else {
      reply.send({
        authenticated: true,
        user: request.user,
        expiresAt: request.session.expiresAt,
      });
    }
  });
}
```

### API Routes Plugin

```typescript
// src/routes/api.ts
import { FastifyInstance } from 'fastify';

const requireAuth = async (request: any, reply: any) => {
  if (!request.session) {
    reply.code(401).send({ error: 'Authentication required' });
  }
};

export default async function apiRoutes(fastify: FastifyInstance) {
  // Protected API routes
  fastify.register(async function protectedRoutes(fastify) {
    fastify.addHook('preHandler', requireAuth);

    fastify.get('/me', async (request, reply) => {
      reply.send({
        user: request.user,
        meta: request.session?.meta,
        session: {
          issuedAt: request.session?.issuedAt,
          expiresAt: request.session?.expiresAt,
        },
      });
    });

    fastify.get('/profile', async (request, reply) => {
      reply.send({
        profile: request.user,
        lastLogin: request.session?.meta?.loginTime,
        ip: request.session?.meta?.ip,
      });
    });

    fastify.put('/profile', {
      schema: {
        body: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            preferences: { type: 'object' },
          },
        },
      },
    }, async (request, reply) => {
      // Update user profile logic here
      const { name, preferences } = request.body as any;

      // This would typically update a database
      reply.send({
        success: true,
        updated: { name, preferences },
      });
    });

    fastify.get('/admin/users', {
      preHandler: async (request, reply) => {
        try {
          (request as any).requireRole('admin');
        } catch (error) {
          reply.code(403).send({ error: error.message });
        }
      }
    }, async (request, reply) => {
      // Admin only endpoint
      reply.send({
        users: [
          { id: '1', name: 'Admin User', role: 'admin' },
          { id: '2', name: 'Regular User', role: 'user' },
        ],
      });
    });
  });

  // Public API routes
  fastify.get('/health', async (request, reply) => {
    reply.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
    });
  });

  fastify.get('/status', async (request, reply) => {
    reply.send({
      server: 'running',
      auth: 'configured',
      environment: process.env.NODE_ENV || 'development',
    });
  });
}
```

## Main Application with Plugins

```typescript
// src/app.ts
import Fastify from 'fastify';

const fastify = Fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    prettyPrint: process.env.NODE_ENV !== 'production',
  },
});

// Register plugins
await fastify.register(import('@fastify/cookie'));
await fastify.register(import('@fastify/formbody'));
await fastify.register(import('@fastify/cors'), {
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
});

// Custom plugins
await fastify.register(import('./plugins/auth'));
await fastify.register(import('./plugins/rateLimiting'));

// Routes
await fastify.register(import('./routes/auth'), { prefix: '/auth' });
await fastify.register(import('./routes/api'), { prefix: '/api' });

// Home route
fastify.get('/', async (request, reply) => {
  reply.type('text/html').send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Fastify Auth App</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; }
            .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
            .btn { background: #007cba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; border: none; cursor: pointer; }
            .btn:hover { background: #005a8b; }
            .btn.secondary { background: #6c757d; }
            .user-info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 15px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>🚀 Fastify Auth Demo</h1>
                <p>This is a demonstration of ADAPT Auth SDK integration with Fastify.</p>

                ${request.session ? `
                    <div class="user-info">
                        <strong>Welcome back, ${request.user?.name || request.user?.email}!</strong><br>
                        <small>User ID: ${request.user?.id}</small>
                    </div>
                    <a href="/dashboard" class="btn">Dashboard</a>
                    <a href="/api/me" class="btn">API Data</a>
                    <form method="post" action="/auth/logout" style="display: inline;">
                        <button type="submit" class="btn secondary">Logout</button>
                    </form>
                ` : `
                    <p>Please sign in to access protected features.</p>
                    <a href="/auth/login" class="btn">Sign In with Stanford</a>
                `}

                <hr style="margin: 30px 0;">
                <h3>API Endpoints</h3>
                <ul>
                    <li><a href="/api/health">Health Check</a></li>
                    <li><a href="/api/status">Server Status</a></li>
                    <li><a href="/auth/session">Session Info</a></li>
                    ${request.session ? '<li><a href="/api/me">User Profile</a></li>' : ''}
                </ul>
            </div>
        </div>
    </body>
    </html>
  `);
});

export default fastify;
```

## Testing

### Unit Tests

```typescript
// tests/auth.test.ts
import { build } from '../src/app';

describe('Authentication', () => {
  const app = build();

  afterAll(async () => {
    await app.close();
  });

  describe('GET /auth/login', () => {
    it('should redirect to SAML login URL', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/auth/login',
      });

      expect(response.statusCode).toBe(302);
      expect(response.headers.location).toContain('stanford.edu');
    });
  });

  describe('GET /api/health', () => {
    it('should return health status', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/health',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.status).toBe('ok');
    });
  });

  describe('Protected routes', () => {
    it('should return 401 for unauthenticated API requests', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/me',
      });

      expect(response.statusCode).toBe(401);
    });
  });
});
```

This Fastify example demonstrates a high-performance authentication setup with plugins, hooks, route organization, and comprehensive error handling.

# Node.js with Web Standards Example

This example demonstrates how to use ADAPT Auth SDK with vanilla Node.js using Web Standards APIs (Request, Response, URL, etc.), making it compatible with modern runtimes like Bun, Deno, and Node.js 18+.

## Setup

### 1. Install Dependencies

```bash
npm install adapt-auth-sdk
# Or with other runtimes:
# bun add adapt-auth-sdk
# deno add npm:adapt-auth-sdk
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

## Web Standards Server

### Main Server

```typescript
// src/server.ts
import { samlProvider, sessionManager } from './auth.ts';

interface AuthenticatedRequest extends Request {
  session?: {
    user: any;
    meta?: Record<string, unknown>;
    issuedAt: number;
    expiresAt: number;
  };
  user?: any;
}

class AuthServer {
  private routes = new Map<string, (request: Request) => Promise<Response>>();

  constructor() {
    this.setupRoutes();
  }

  private setupRoutes() {
    // Auth routes
    this.routes.set('GET /auth/login', this.handleLogin.bind(this));
    this.routes.set('POST /auth/acs', this.handleCallback.bind(this));
    this.routes.set('POST /auth/logout', this.handleLogout.bind(this));
    this.routes.set('GET /auth/session', this.handleSessionInfo.bind(this));

    // Protected routes
    this.routes.set('GET /dashboard', this.handleDashboard.bind(this));
    this.routes.set('GET /profile', this.handleProfile.bind(this));

    // API routes
    this.routes.set('GET /api/me', this.handleApiMe.bind(this));
    this.routes.set('GET /api/session', this.handleApiSession.bind(this));
    this.routes.set('GET /api/health', this.handleHealth.bind(this));

    // Public routes
    this.routes.set('GET /', this.handleHome.bind(this));
  }

  async handle(request: Request): Promise<Response> {
    try {
      // Add session to request
      const authRequest = await this.addSessionToRequest(request);

      // Route matching
      const url = new URL(request.url);
      const routeKey = `${request.method} ${url.pathname}`;
      const handler = this.routes.get(routeKey);

      if (handler) {
        return await handler(authRequest);
      }

      // 404 Not Found
      return new Response('Not Found', {
        status: 404,
        headers: { 'Content-Type': 'text/plain' }
      });
    } catch (error) {
      console.error('Request handling error:', error);
      return new Response('Internal Server Error', {
        status: 500,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
  }

  private async addSessionToRequest(request: Request): Promise<AuthenticatedRequest> {
    try {
      const session = await sessionManager.getSession(request);
      return Object.assign(request, {
        session,
        user: session?.user,
      });
    } catch (error) {
      console.error('Session error:', error);
      return request as AuthenticatedRequest;
    }
  }

  private requireAuth(request: AuthenticatedRequest): Response | null {
    if (!request.session) {
      const url = new URL(request.url);

      if (url.pathname.startsWith('/api/')) {
        return Response.json({ error: 'Authentication required' }, { status: 401 });
      } else {
        const loginUrl = `/auth/login?returnTo=${encodeURIComponent(url.pathname)}`;
        return Response.redirect(loginUrl, 302);
      }
    }
    return null;
  }

  // Auth handlers
  async handleLogin(request: AuthenticatedRequest): Promise<Response> {
    try {
      const url = new URL(request.url);
      const returnTo = url.searchParams.get('returnTo') || '/dashboard';
      const { url: loginUrl } = await samlProvider.getLoginUrl(request, { returnTo });
      return Response.redirect(loginUrl, 302);
    } catch (error) {
      console.error('Login error:', error);
      return new Response('Login failed', { status: 500 });
    }
  }

  async handleCallback(request: AuthenticatedRequest): Promise<Response> {
    try {
      const profile = await samlProvider.handleCallback(request);

      // Create session
      const response = await sessionManager.createSession(request, {
        user: {
          id: profile.nameID,
          email: profile.email || profile.mail,
          name: profile.displayName || `${profile.givenName} ${profile.sn}`,
          imageUrl: profile.picture,
        },
        meta: {
          loginTime: new Date().toISOString(),
          userAgent: request.headers.get('user-agent'),
          ip: this.getClientIP(request),
        },
      });

      // Get return URL from RelayState
      const formData = await request.formData();
      const returnTo = formData.get('RelayState') as string || '/dashboard';

      return Response.redirect(returnTo, 302);
    } catch (error) {
      console.error('Callback error:', error);
      return new Response('Authentication failed', { status: 400 });
    }
  }

  async handleLogout(request: AuthenticatedRequest): Promise<Response> {
    const authRequired = this.requireAuth(request);
    if (authRequired) return authRequired;

    try {
      await sessionManager.destroySession(request);

      const acceptsJson = request.headers.get('accept')?.includes('application/json');
      if (acceptsJson) {
        return Response.json({ success: true });
      } else {
        return Response.redirect('/', 302);
      }
    } catch (error) {
      console.error('Logout error:', error);
      return new Response('Logout failed', { status: 500 });
    }
  }

  async handleSessionInfo(request: AuthenticatedRequest): Promise<Response> {
    if (!request.session) {
      return Response.json({ authenticated: false });
    }

    return Response.json({
      authenticated: true,
      user: request.user,
      expiresAt: request.session.expiresAt,
    });
  }

  // Page handlers
  async handleHome(request: AuthenticatedRequest): Promise<Response> {
    const isAuthenticated = !!request.session;

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Web Standards Auth Demo</title>
          <style>
              body { font-family: system-ui, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
              .container { max-width: 600px; margin: 0 auto; }
              .card { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
              .btn { background: #007cba; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; border: none; cursor: pointer; }
              .btn:hover { background: #005a8b; }
              .btn.secondary { background: #6c757d; }
              .user-info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 15px 0; }
              ul { text-align: left; max-width: 300px; margin: 20px auto; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="card">
                  <h1>🌐 Web Standards Auth Demo</h1>
                  <p>Built with vanilla Node.js using Web Standards APIs</p>

                  ${isAuthenticated ? `
                      <div class="user-info">
                          <strong>Welcome, ${request.user?.name || request.user?.email}!</strong><br>
                          <small>User ID: ${request.user?.id}</small>
                      </div>
                      <a href="/dashboard" class="btn">Dashboard</a>
                      <a href="/profile" class="btn">Profile</a>
                      <form method="post" action="/auth/logout" style="display: inline;">
                          <button type="submit" class="btn secondary">Logout</button>
                      </form>
                  ` : `
                      <p>Please sign in to access protected features</p>
                      <a href="/auth/login" class="btn">Sign In with Stanford</a>
                  `}

                  <hr style="margin: 30px 0;">
                  <h3>Available Endpoints</h3>
                  <ul>
                      <li><a href="/api/health">Health Check</a></li>
                      <li><a href="/auth/session">Session Info</a></li>
                      ${isAuthenticated ? '<li><a href="/api/me">User Profile API</a></li>' : ''}
                  </ul>
              </div>
          </div>
      </body>
      </html>
    `;

    return new Response(html, {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  async handleDashboard(request: AuthenticatedRequest): Promise<Response> {
    const authRequired = this.requireAuth(request);
    if (authRequired) return authRequired;

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Dashboard</title>
          <style>
              body { font-family: system-ui, sans-serif; margin: 20px; }
              .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
              .btn { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; display: inline-block; }
              .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
              pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow: auto; }
          </style>
      </head>
      <body>
          <h1>Dashboard</h1>

          <div class="grid">
              <div class="card">
                  <h2>Welcome, ${request.user?.name || request.user?.email}!</h2>
                  <p>User ID: ${request.user?.id}</p>
                  ${request.user?.imageUrl ? `<img src="${request.user.imageUrl}" alt="Profile" width="64" height="64" style="border-radius: 50%;">` : ''}

                  <div style="margin-top: 20px;">
                      <a href="/profile" class="btn">View Profile</a>
                      <a href="/api/me" class="btn">API Data</a>
                      <a href="/" class="btn" style="background: #6c757d;">Home</a>
                  </div>
              </div>

              <div class="card">
                  <h3>Session Information</h3>
                  <p><strong>Login Time:</strong> ${request.session?.meta?.loginTime}</p>
                  <p><strong>Expires:</strong> ${new Date(request.session?.expiresAt || 0).toLocaleString()}</p>
                  <p><strong>User Agent:</strong> ${request.session?.meta?.userAgent}</p>

                  <button onclick="refreshSession()" class="btn">Refresh Session</button>
              </div>
          </div>

          <script>
              async function refreshSession() {
                  try {
                      const response = await fetch('/auth/session');
                      const data = await response.json();
                      alert('Session refreshed! Expires: ' + new Date(data.expiresAt).toLocaleString());
                  } catch (error) {
                      alert('Failed to refresh session: ' + error.message);
                  }
              }
          </script>
      </body>
      </html>
    `;

    return new Response(html, {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  async handleProfile(request: AuthenticatedRequest): Promise<Response> {
    const authRequired = this.requireAuth(request);
    if (authRequired) return authRequired;

    const html = `
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>User Profile</title>
          <style>
              body { font-family: system-ui, sans-serif; margin: 20px; }
              .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin: 20px 0; }
              .btn { background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; margin: 5px; display: inline-block; }
              pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow: auto; font-size: 14px; }
          </style>
      </head>
      <body>
          <h1>User Profile</h1>

          <div class="card">
              <h2>User Data</h2>
              <pre>${JSON.stringify(request.user, null, 2)}</pre>
          </div>

          <div class="card">
              <h2>Session Metadata</h2>
              <pre>${JSON.stringify(request.session?.meta, null, 2)}</pre>
          </div>

          <div class="card">
              <h2>Session Details</h2>
              <p><strong>Issued At:</strong> ${new Date(request.session?.issuedAt || 0).toLocaleString()}</p>
              <p><strong>Expires At:</strong> ${new Date(request.session?.expiresAt || 0).toLocaleString()}</p>
              <p><strong>Time Remaining:</strong> <span id="timeRemaining">Calculating...</span></p>
          </div>

          <a href="/dashboard" class="btn">Back to Dashboard</a>

          <script>
              function updateTimeRemaining() {
                  const expiresAt = ${request.session?.expiresAt || 0};
                  const now = Date.now();
                  const remaining = expiresAt - now;

                  if (remaining > 0) {
                      const hours = Math.floor(remaining / (1000 * 60 * 60));
                      const minutes = Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60));
                      const seconds = Math.floor((remaining % (1000 * 60)) / 1000);
                      document.getElementById('timeRemaining').textContent =
                          \`\${hours}h \${minutes}m \${seconds}s\`;
                  } else {
                      document.getElementById('timeRemaining').textContent = 'Session expired';
                  }
              }

              updateTimeRemaining();
              setInterval(updateTimeRemaining, 1000);
          </script>
      </body>
      </html>
    `;

    return new Response(html, {
      headers: { 'Content-Type': 'text/html' }
    });
  }

  // API handlers
  async handleApiMe(request: AuthenticatedRequest): Promise<Response> {
    const authRequired = this.requireAuth(request);
    if (authRequired) return authRequired;

    return Response.json({
      user: request.user,
      meta: request.session?.meta,
      session: {
        issuedAt: request.session?.issuedAt,
        expiresAt: request.session?.expiresAt,
      },
    });
  }

  async handleApiSession(request: AuthenticatedRequest): Promise<Response> {
    if (!request.session) {
      return Response.json({ authenticated: false });
    }

    return Response.json({
      authenticated: true,
      user: request.user,
      expiresAt: request.session.expiresAt,
    });
  }

  async handleHealth(request: AuthenticatedRequest): Promise<Response> {
    return Response.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      version: process.version,
    });
  }

  private getClientIP(request: Request): string {
    return (
      request.headers.get('x-forwarded-for') ||
      request.headers.get('x-real-ip') ||
      'unknown'
    );
  }
}

// Create server instance
const authServer = new AuthServer();

// Start server based on runtime
if (typeof Bun !== 'undefined') {
  // Bun runtime
  const server = Bun.serve({
    port: parseInt(process.env.PORT || '3000'),
    async fetch(request) {
      return authServer.handle(request);
    },
  });

  console.log(`🔥 Bun server running at http://localhost:${server.port}`);
} else if (typeof Deno !== 'undefined') {
  // Deno runtime
  const port = parseInt(Deno.env.get('PORT') || '3000');

  Deno.serve({ port }, (request) => authServer.handle(request));
  console.log(`🦕 Deno server running at http://localhost:${port}`);
} else {
  // Node.js runtime
  const { createServer } = await import('node:http');

  const server = createServer(async (req, res) => {
    try {
      // Convert Node.js request to Web Standards Request
      const url = `http://${req.headers.host}${req.url}`;
      const body = req.method !== 'GET' && req.method !== 'HEAD'
        ? await new Promise<Buffer>((resolve) => {
            const chunks: Buffer[] = [];
            req.on('data', (chunk) => chunks.push(chunk));
            req.on('end', () => resolve(Buffer.concat(chunks)));
          })
        : undefined;

      const request = new Request(url, {
        method: req.method,
        headers: req.headers as HeadersInit,
        body: body,
      });

      // Handle request
      const response = await authServer.handle(request);

      // Convert Web Standards Response to Node.js response
      res.statusCode = response.status;

      response.headers.forEach((value, key) => {
        res.setHeader(key, value);
      });

      if (response.body) {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          res.write(value);
        }
      }

      res.end();
    } catch (error) {
      console.error('Server error:', error);
      res.statusCode = 500;
      res.end('Internal Server Error');
    }
  });

  const port = parseInt(process.env.PORT || '3000');
  server.listen(port, () => {
    console.log(`🚀 Node.js server running at http://localhost:${port}`);
  });
}

export { authServer };
```

## Runtime-Specific Configurations

### Bun Configuration

```typescript
// bun.config.ts
export default {
  entrypoint: 'src/server.ts',
  outdir: 'dist',
  target: 'bun',
  minify: process.env.NODE_ENV === 'production',
  env: {
    NODE_ENV: process.env.NODE_ENV || 'development',
  },
};
```

### Deno Configuration

```typescript
// deno.json
{
  "tasks": {
    "start": "deno run --allow-net --allow-env --allow-read src/server.ts",
    "dev": "deno run --allow-net --allow-env --allow-read --watch src/server.ts"
  },
  "imports": {
    "adapt-auth-sdk": "npm:adapt-auth-sdk"
  },
  "compilerOptions": {
    "lib": ["dom", "deno.ns"]
  }
}
```

### Node.js Package Configuration

```json
// package.json
{
  "name": "web-standards-auth-example",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node dist/server.js",
    "dev": "tsx watch src/server.ts",
    "build": "tsc"
  },
  "dependencies": {
    "adapt-auth-sdk": "^2.0.0"
  },
  "devDependencies": {
    "@types/node": "^20.0.0",
    "tsx": "^4.0.0",
    "typescript": "^5.0.0"
  }
}
```

## Deployment Examples

### Bun Dockerfile

```dockerfile
# Dockerfile.bun
FROM oven/bun:latest

WORKDIR /app

COPY package.json bun.lockb ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

EXPOSE 3000

CMD ["bun", "run", "dist/server.js"]
```

### Deno Deploy

```typescript
// deploy.ts
import { authServer } from './src/server.ts';

export default {
  async fetch(request: Request) {
    return authServer.handle(request);
  },
};
```

### Node.js Dockerfile

```dockerfile
# Dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["node", "dist/server.js"]
```

## Testing

### Cross-Runtime Tests

```typescript
// tests/server.test.ts
import { authServer } from '../src/server';

describe('Web Standards Auth Server', () => {
  test('GET / returns home page', async () => {
    const request = new Request('http://localhost:3000/');
    const response = await authServer.handle(request);

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('text/html');
  });

  test('GET /api/health returns health status', async () => {
    const request = new Request('http://localhost:3000/api/health');
    const response = await authServer.handle(request);

    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.status).toBe('ok');
  });

  test('GET /api/me requires authentication', async () => {
    const request = new Request('http://localhost:3000/api/me');
    const response = await authServer.handle(request);

    expect(response.status).toBe(401);
  });

  test('GET /dashboard redirects to login', async () => {
    const request = new Request('http://localhost:3000/dashboard');
    const response = await authServer.handle(request);

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toContain('/auth/login');
  });
});
```

This Web Standards example demonstrates a runtime-agnostic approach that works seamlessly across Bun, Deno, and Node.js while providing full authentication functionality.

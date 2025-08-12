# Express.js Example

This example demonstrates how to integrate ADAPT Auth SDK with an Express.js application using the core SDK functionality.

## Setup

### 1. Install Dependencies

```bash
npm install express adapt-auth-sdk
npm install -D @types/express
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

### 3. Basic Configuration

```typescript
// src/auth.ts
import { SAMLProvider, SessionManager } from 'adapt-auth-sdk';

export const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
  relayStateSecret: process.env.ADAPT_AUTH_RELAY_STATE_SECRET,
}, {
  verbose: process.env.NODE_ENV === 'development',
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

## Express Application

### Main Application

```typescript
// src/app.ts
import express from 'express';
import cors from 'cors';
import { samlProvider, sessionManager } from './auth';

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// View engine (optional)
app.set('view engine', 'ejs');
app.set('views', './views');

// Authentication middleware
async function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  try {
    const session = await sessionManager.getSession(req, res);

    if (!session) {
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Authentication required' });
      } else {
        return res.redirect(`/auth/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
      }
    }

    // Add session to request
    (req as any).session = session;
    (req as any).user = session.user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Authentication error' });
  }
}

// Auth routes
app.get('/auth/login', async (req, res) => {
  try {
    const returnTo = req.query.returnTo as string;
    const { url } = await samlProvider.getLoginUrl(req, { returnTo });
    res.redirect(url);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send('Login failed');
  }
});

app.post('/auth/acs', async (req, res) => {
  try {
    const profile = await samlProvider.handleCallback(req);

    // Create session
    await sessionManager.createSession(req, res, {
      user: {
        id: profile.nameID,
        email: profile.email || profile.mail,
        name: profile.displayName || `${profile.givenName} ${profile.sn}`,
        imageUrl: profile.picture,
      },
      meta: {
        loginTime: new Date().toISOString(),
        samlAttributes: profile,
      },
    });

    // Redirect to return URL or home
    const returnTo = req.body.RelayState || '/dashboard';
    res.redirect(returnTo);
  } catch (error) {
    console.error('Callback error:', error);
    res.status(400).send('Authentication failed');
  }
});

app.post('/auth/logout', requireAuth, async (req, res) => {
  try {
    await sessionManager.destroySession(req, res);
    res.redirect('/');
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).send('Logout failed');
  }
});

// Protected routes
app.get('/dashboard', requireAuth, (req, res) => {
  const user = (req as any).user;
  res.render('dashboard', { user });
});

app.get('/profile', requireAuth, (req, res) => {
  const user = (req as any).user;
  const session = (req as any).session;
  res.render('profile', { user, session });
});

// API routes
app.get('/api/me', requireAuth, (req, res) => {
  const user = (req as any).user;
  const session = (req as any).session;

  res.json({
    user,
    meta: session.meta,
    issuedAt: session.issuedAt,
    expiresAt: session.expiresAt,
  });
});

app.get('/api/session', async (req, res) => {
  try {
    const session = await sessionManager.getSession(req, res);

    if (!session) {
      return res.json({ authenticated: false });
    }

    res.json({
      authenticated: true,
      user: session.user,
    });
  } catch (error) {
    res.status(500).json({ error: 'Session check failed' });
  }
});

// Public routes
app.get('/', (req, res) => {
  res.render('index');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

export default app;
```

## Middleware Examples

### Role-Based Access Control

```typescript
// src/middleware/rbac.ts
import { Request, Response, NextFunction } from 'express';

interface AuthenticatedRequest extends Request {
  user: any;
  session: any;
}

export function requireRole(role: string) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userRoles = req.session?.meta?.roles || [];

    if (!userRoles.includes(role)) {
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({ error: `Missing required role: ${role}` });
      } else {
        return res.status(403).render('403', { requiredRole: role });
      }
    }

    next();
  };
}

export function requireAnyRole(roles: string[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const userRoles = req.session?.meta?.roles || [];
    const hasRole = roles.some(role => userRoles.includes(role));

    if (!hasRole) {
      if (req.path.startsWith('/api/')) {
        return res.status(403).json({
          error: `Missing required role. Need one of: ${roles.join(', ')}`
        });
      } else {
        return res.status(403).render('403', { requiredRoles: roles });
      }
    }

    next();
  };
}

// Usage
app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  res.render('admin');
});

app.get('/moderator', requireAuth, requireAnyRole(['admin', 'moderator']), (req, res) => {
  res.render('moderator');
});
```

### Session Refresh

```typescript
// src/middleware/sessionRefresh.ts
import { Request, Response, NextFunction } from 'express';
import { sessionManager } from '../auth';

export async function refreshSession(req: Request, res: Response, next: NextFunction) {
  try {
    const session = await sessionManager.getSession(req, res);

    if (session) {
      const now = Date.now();
      const timeSinceIssued = now - session.issuedAt;
      const refreshThreshold = 30 * 60 * 1000; // 30 minutes

      // Refresh session if it's been more than 30 minutes since last refresh
      if (timeSinceIssued > refreshThreshold) {
        await sessionManager.refreshSession(req, res, session);
      }
    }

    next();
  } catch (error) {
    console.error('Session refresh error:', error);
    next();
  }
}

// Use in your routes
app.use('/dashboard', refreshSession);
app.use('/api', refreshSession);
```

## View Templates

### Layout Template

```html
<!-- views/layout.ejs -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My App</title>
    <link href="/styles.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">
            <a href="/">My App</a>
        </div>
        <div class="nav-links">
            <% if (locals.user) { %>
                <span>Welcome, <%= user.name || user.email %>!</span>
                <a href="/dashboard">Dashboard</a>
                <a href="/profile">Profile</a>
                <form method="post" action="/auth/logout" style="display: inline;">
                    <button type="submit">Logout</button>
                </form>
            <% } else { %>
                <a href="/auth/login">Login</a>
            <% } %>
        </div>
    </nav>

    <main>
        <%- body %>
    </main>

    <script src="/app.js"></script>
</body>
</html>
```

### Dashboard Template

```html
<!-- views/dashboard.ejs -->
<%- include('layout', { body: capture(() => { %>
    <div class="dashboard">
        <h1>Dashboard</h1>
        <div class="user-info">
            <h2>Welcome, <%= user.name || user.email %>!</h2>
            <p>User ID: <%= user.id %></p>

            <% if (user.imageUrl) { %>
                <img src="<%= user.imageUrl %>" alt="Profile" width="64" height="64">
            <% } %>
        </div>

        <div class="actions">
            <a href="/profile" class="btn">View Profile</a>
            <a href="/api/me" class="btn">API Data</a>
        </div>

        <div class="quick-stats">
            <h3>Quick Stats</h3>
            <ul>
                <li>Last login: <span id="last-login">Loading...</span></li>
                <li>Session expires: <span id="session-expires">Loading...</span></li>
            </ul>
        </div>
    </div>

    <script>
        // Load session info
        fetch('/api/me')
            .then(res => res.json())
            .then(data => {
                document.getElementById('last-login').textContent =
                    new Date(data.meta.loginTime).toLocaleString();
                document.getElementById('session-expires').textContent =
                    new Date(data.expiresAt).toLocaleString();
            })
            .catch(err => console.error('Failed to load session info:', err));
    </script>
<% }) %> <%- user %>
```

## API Client Integration

### Frontend JavaScript Client

```javascript
// public/app.js
class AuthClient {
  constructor() {
    this.baseUrl = '';
  }

  async getSession() {
    try {
      const response = await fetch('/api/session');
      return await response.json();
    } catch (error) {
      console.error('Failed to get session:', error);
      return { authenticated: false };
    }
  }

  async getUser() {
    try {
      const response = await fetch('/api/me');
      if (response.ok) {
        return await response.json();
      }
      return null;
    } catch (error) {
      console.error('Failed to get user:', error);
      return null;
    }
  }

  login(returnTo = window.location.pathname) {
    window.location.href = `/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
  }

  async logout() {
    try {
      const response = await fetch('/auth/logout', { method: 'POST' });
      if (response.ok) {
        window.location.href = '/';
      }
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }
}

// Initialize client
const auth = new AuthClient();

// Auto-check session on page load
document.addEventListener('DOMContentLoaded', async () => {
  const session = await auth.getSession();

  if (session.authenticated) {
    console.log('User is authenticated:', session.user);
  } else {
    console.log('User is not authenticated');
  }
});
```

## Advanced Configuration

### Custom Profile Mapping

```typescript
// src/auth.ts
import { SAMLProvider, SessionManager } from 'adapt-auth-sdk';

export const samlProvider = new SAMLProvider({
  issuer: process.env.ADAPT_AUTH_SAML_ENTITY!,
  idpCert: process.env.ADAPT_AUTH_SAML_CERT!,
  returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN!,
}, {
  callbacks: {
    async mapProfile(profile) {
      // Custom mapping from SAML attributes
      return {
        id: profile.nameID,
        email: profile.email || profile.mail,
        name: profile.displayName || `${profile.givenName} ${profile.sn}`,
        imageUrl: profile.picture,
        department: profile.department,
        title: profile.title,
        roles: profile.roles?.split(',') || [],
        sunetId: profile.sunetId,
      };
    },
  },
});
```

### Database Integration

```typescript
// src/middleware/userSync.ts
import { Request, Response, NextFunction } from 'express';
import { getUserById, createUser, updateUser } from '../database/users';

export async function syncUserToDatabase(req: Request, res: Response, next: NextFunction) {
  const session = (req as any).session;

  if (session?.user) {
    try {
      let dbUser = await getUserById(session.user.id);

      if (!dbUser) {
        // Create new user in database
        dbUser = await createUser({
          id: session.user.id,
          email: session.user.email,
          name: session.user.name,
          lastLogin: new Date(),
        });
      } else {
        // Update last login
        await updateUser(session.user.id, {
          lastLogin: new Date(),
          email: session.user.email,
          name: session.user.name,
        });
      }

      // Add database user to request
      (req as any).dbUser = dbUser;
    } catch (error) {
      console.error('User sync error:', error);
      // Continue without database sync
    }
  }

  next();
}
```

## Testing

### Unit Tests

```typescript
// tests/auth.test.ts
import request from 'supertest';
import app from '../src/app';

describe('Authentication', () => {
  describe('GET /auth/login', () => {
    it('should redirect to SAML login URL', async () => {
      const response = await request(app)
        .get('/auth/login')
        .expect(302);

      expect(response.headers.location).toContain('stanford.edu');
    });
  });

  describe('GET /api/session', () => {
    it('should return unauthenticated for no session', async () => {
      const response = await request(app)
        .get('/api/session')
        .expect(200);

      expect(response.body).toEqual({ authenticated: false });
    });
  });

  describe('Protected routes', () => {
    it('should redirect unauthenticated users', async () => {
      await request(app)
        .get('/dashboard')
        .expect(302)
        .expect('Location', /\/auth\/login/);
    });
  });
});
```

This Express.js example provides a complete server-side authentication implementation with middleware, templates, API endpoints, and advanced features like role-based access control and database integration.

# Gatsby Integration Examples

This guide shows how to integrate ADAPT Auth SDK with Gatsby for Stanford WebAuth SAML authentication.

## Overview

Gatsby integration uses:
- **Server-Side Rendering (SSR)** for authentication routes
- **Gatsby Functions** for API endpoints
- **Client-side routing** with authentication guards
- **Netlify deployment** for production

## Project Structure

```
src/
├── pages/
│   ├── index.js              # Public home page
│   ├── protected.js          # Protected page example
│   └── login.js             # Login page
├── api/
│   ├── auth/
│   │   ├── login.js         # SAML login initiation
│   │   ├── acs.js           # SAML callback handler
│   │   ├── logout.js        # Logout handler
│   │   └── session.js       # Session status check
├── components/
│   ├── AuthGuard.js         # Route protection component
│   ├── LoginButton.js       # Login/logout UI
│   └── UserProfile.js       # User info display
└── hooks/
    └── useAuth.js           # Authentication hook
```

## Environment Setup

Create `.env.development` and `.env.production`:

```bash
# Required for SAML authentication
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----
ADAPT_AUTH_SAML_RETURN_ORIGIN=http://localhost:8000  # or https://yoursite.netlify.app
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key

# Optional RelayState signing
ADAPT_AUTH_RELAY_STATE_SECRET=another-32-character-secret-key

# Gatsby environment indicator
GATSBY_ENV=development  # or production
```

## Authentication Setup

### Core Authentication Configuration

```javascript
// src/auth/config.js
const authConfig = {
  saml: {
    // Required SAML configuration
    issuer: process.env.ADAPT_AUTH_SAML_ENTITY,
    idpCert: process.env.ADAPT_AUTH_SAML_CERT,
    returnToOrigin: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN,

    // Optional configuration
    relayStateSecret: process.env.ADAPT_AUTH_RELAY_STATE_SECRET,
    includeReturnTo: true, // Enable returnTo URL functionality

    // SAML endpoints (Stanford WebAuth defaults)
    idpUrl: 'https://login.stanford.edu/idp/profile/SAML2/Redirect/SSO',
    acsPath: '/api/auth/acs',

    // Clock skew tolerance
    clockTolerance: 60, // 60 seconds
  },
  session: {
    // Required session configuration
    name: 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET,

    // Cookie configuration
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      // Session-only cookies (no maxAge)
    },

    // Cookie size monitoring
    cookieSizeThreshold: 3500,
  },

  // Enable verbose logging in development
  verbose: process.env.NODE_ENV === 'development',
};

export default authConfig;
```

## API Functions (Gatsby Functions)

### Login Handler

```javascript
// src/api/auth/login.js
import { SAMLProvider, SessionManager, createWebCookieStore } from 'adapt-auth-sdk';
import authConfig from '../../auth/config';

const samlProvider = new SAMLProvider(authConfig.saml);

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Get returnTo from query parameters
    const returnTo = req.query.returnTo;

    // Generate SAML authentication request
    const { redirectUrl } = await samlProvider.login({
      returnTo: returnTo || '/', // Default to home page
    });

    // Redirect to Stanford WebAuth
    res.redirect(302, redirectUrl);
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Authentication failed' });
  }
}
```

### SAML Callback Handler (ACS)

```javascript
// src/api/auth/acs.js
import { SAMLProvider, SessionManager, createWebCookieStore } from 'adapt-auth-sdk';
import authConfig from '../../auth/config';

const samlProvider = new SAMLProvider(authConfig.saml);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Process SAML response
    const result = await samlProvider.handleCallback(req.body);

    if (!result.success) {
      console.error('SAML callback failed:', result.error);
      return res.redirect(302, '/login?error=auth_failed');
    }

    // Create session
    const cookieStore = createWebCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, authConfig.session);

    await sessionManager.createSession({
      user: {
        id: result.user.nameID,
        email: result.user.email,
        name: result.user.displayName,
        // Add other user attributes as needed
      },
      meta: {
        roles: result.user.roles || [],
        affiliation: result.user.affiliation,
      },
    });

    // Redirect to returnTo URL or default
    const returnTo = result.returnTo || '/';
    res.redirect(302, returnTo);
  } catch (error) {
    console.error('ACS error:', error);
    res.redirect(302, '/login?error=callback_failed');
  }
}
```

### Session Status Handler

```javascript
// src/api/auth/session.js
import { SessionManager, createWebCookieStore } from 'adapt-auth-sdk';
import authConfig from '../../auth/config';

export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const cookieStore = createWebCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, authConfig.session);

    const session = await sessionManager.getSession();

    if (!session) {
      return res.status(401).json({
        authenticated: false,
        user: null
      });
    }

    res.json({
      authenticated: true,
      user: session.user,
      meta: session.meta,
    });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({ error: 'Session check failed' });
  }
}
```

### Logout Handler

```javascript
// src/api/auth/logout.js
import { SessionManager, createWebCookieStore } from 'adapt-auth-sdk';
import authConfig from '../../auth/config';

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const cookieStore = createWebCookieStore(req, res);
    const sessionManager = new SessionManager(cookieStore, authConfig.session);

    // Clear session
    await sessionManager.destroySession();

    res.json({ success: true });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
}
```

## Client-Side Integration

### Authentication Hook

```javascript
// src/hooks/useAuth.js
import { useState, useEffect, createContext, useContext } from 'react';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const checkSession = async () => {
    try {
      const response = await fetch('/api/auth/session');

      if (response.ok) {
        const data = await response.json();
        setUser(data.authenticated ? data.user : null);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Session check failed:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const login = (returnTo = '/') => {
    window.location.href = `/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`;
  };

  const logout = async () => {
    try {
      await fetch('/api/auth/logout', { method: 'POST' });
      setUser(null);
      window.location.href = '/';
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };

  useEffect(() => {
    checkSession();
  }, []);

  return (
    <AuthContext.Provider value={{
      user,
      loading,
      isAuthenticated: !!user,
      login,
      logout,
      refreshSession: checkSession,
    }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
```

### Authentication Guard Component

```javascript
// src/components/AuthGuard.js
import React from 'react';
import { useAuth } from '../hooks/useAuth';

const AuthGuard = ({ children, fallback = null, redirectTo = '/login' }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    if (typeof window !== 'undefined') {
      // Client-side redirect
      window.location.href = `${redirectTo}?returnTo=${encodeURIComponent(window.location.pathname)}`;
      return null;
    }

    // Server-side fallback
    return fallback || <div>Authentication required</div>;
  }

  return children;
};

export default AuthGuard;
```

### Login/Logout Button Component

```javascript
// src/components/LoginButton.js
import React from 'react';
import { useAuth } from '../hooks/useAuth';

const LoginButton = ({ className = '', returnTo }) => {
  const { isAuthenticated, user, login, logout } = useAuth();

  if (isAuthenticated) {
    return (
      <div className={className}>
        <span>Welcome, {user?.name || user?.email}!</span>
        <button onClick={logout} className="ml-2 btn-logout">
          Logout
        </button>
      </div>
    );
  }

  return (
    <button
      onClick={() => login(returnTo)}
      className={`btn-login ${className}`}
    >
      Login with Stanford WebAuth
    </button>
  );
};

export default LoginButton;
```

## Page Examples

### Protected Page

```javascript
// src/pages/protected.js
import React from 'react';
import { AuthProvider } from '../hooks/useAuth';
import AuthGuard from '../components/AuthGuard';
import LoginButton from '../components/LoginButton';

const ProtectedPage = () => {
  return (
    <AuthProvider>
      <div>
        <h1>Protected Page</h1>
        <AuthGuard>
          <div>
            <p>This content is only visible to authenticated users!</p>
            <LoginButton />
          </div>
        </AuthGuard>
      </div>
    </AuthProvider>
  );
};

export default ProtectedPage;
export const Head = () => <title>Protected Page</title>;
```

### Login Page

```javascript
// src/pages/login.js
import React, { useEffect } from 'react';
import { AuthProvider, useAuth } from '../hooks/useAuth';

const LoginPageContent = () => {
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    // Redirect if already authenticated
    if (isAuthenticated && typeof window !== 'undefined') {
      const urlParams = new URLSearchParams(window.location.search);
      const returnTo = urlParams.get('returnTo') || '/';
      window.location.href = returnTo;
    }
  }, [isAuthenticated]);

  if (isAuthenticated) {
    return <div>Redirecting...</div>;
  }

  return (
    <div className="login-page">
      <h1>Login Required</h1>
      <p>Please log in with your Stanford credentials to continue.</p>
      <LoginButton returnTo={typeof window !== 'undefined' ?
        new URLSearchParams(window.location.search).get('returnTo') || '/' : '/'}
      />
    </div>
  );
};

const LoginPage = () => {
  return (
    <AuthProvider>
      <LoginPageContent />
    </AuthProvider>
  );
};

export default LoginPage;
export const Head = () => <title>Login - Stanford WebAuth</title>;
```

## Gatsby Configuration

### gatsby-config.js

```javascript
// gatsby-config.js
module.exports = {
  siteMetadata: {
    title: 'Your Gatsby App',
    siteUrl: process.env.ADAPT_AUTH_SAML_RETURN_ORIGIN,
  },
  plugins: [
    // ... other plugins
    {
      resolve: 'gatsby-plugin-env-variables',
      options: {
        allowList: ['GATSBY_ENV']
      }
    },
  ],
};
```

## Netlify Deployment

### netlify.toml

```toml
[build]
  command = "gatsby build"
  functions = "src/api"
  publish = "public"

[dev]
  framework = "gatsby"
  targetPort = 8000

# Environment variables for production
[context.production.environment]
  NODE_ENV = "production"

# Redirect for client-side routing
[[redirects]]
  from = "/protected/*"
  to = "/protected/"
  status = 200

# API function routes
[[redirects]]
  from = "/api/*"
  to = "/.netlify/functions/:splat"
  status = 200
```

### Environment Variables in Netlify

Set these in your Netlify dashboard under Site Settings > Environment Variables:

```bash
ADAPT_AUTH_SAML_ENTITY=your-entity-id
ADAPT_AUTH_SAML_CERT=your-certificate-string
ADAPT_AUTH_SAML_RETURN_ORIGIN=https://yoursite.netlify.app
ADAPT_AUTH_SESSION_SECRET=your-32-character-secret-key
ADAPT_AUTH_RELAY_STATE_SECRET=another-32-character-secret-key
NODE_ENV=production
```

## Development Workflow

### Local Development

```bash
# Install dependencies
npm install

# Start Gatsby development server
gatsby develop

# Your app runs on http://localhost:8000
# API functions available at http://localhost:8000/api/*
```

### Testing Authentication

1. **Visit protected page**: `http://localhost:8000/protected`
2. **Redirected to login**: `http://localhost:8000/login`
3. **Click login button**: Redirects to Stanford WebAuth
4. **Complete authentication**: Returns to protected page
5. **Test logout**: User session cleared, redirected to home

### Debugging

Enable verbose logging in development:

```javascript
// src/auth/config.js
export default {
  // ... other config
  verbose: process.env.NODE_ENV === 'development',
  logger: {
    debug: console.log,
    info: console.info,
    warn: console.warn,
    error: console.error,
  },
};
```

## Security Best Practices

### Localhost Development

- ✅ Use HTTP for local development (SAML_RETURN_ORIGIN: `http://localhost:8000`)
- ✅ Store secrets in `.env.development` (gitignored)
- ✅ Use different secrets for dev/prod environments
- ✅ Test with real Stanford credentials

### Netlify Production

- ✅ Use HTTPS for production (SAML_RETURN_ORIGIN: `https://yoursite.netlify.app`)
- ✅ Store secrets in Netlify environment variables
- ✅ Enable secure cookie flags (`secure: true`)
- ✅ Register production URL with Stanford WebAuth

### Session Management

- ✅ **Session-only cookies**: No `maxAge` set (expires when browser closes)
- ✅ **HttpOnly cookies**: Prevent XSS attacks
- ✅ **Secure cookies**: HTTPS only in production
- ✅ **SameSite protection**: Prevent CSRF attacks
- ✅ **Cookie size monitoring**: Warn if session > 3.5KB

## Troubleshooting

### Common Issues

1. **"Authentication failed"**
   ```bash
   # Check SAML configuration
   echo $ADAPT_AUTH_SAML_ENTITY
   echo $ADAPT_AUTH_SAML_CERT

   # Verify certificate format (should have -----BEGIN CERTIFICATE-----)
   ```

2. **"Session check failed"**
   ```bash
   # Verify session secret length (must be 32+ characters)
   echo $ADAPT_AUTH_SESSION_SECRET | wc -c

   # Check cookie configuration
   ```

3. **"404 on API routes"**
   ```bash
   # Check Netlify redirects in netlify.toml
   # Ensure functions are in src/api directory
   ```

### Debug Mode

Enable detailed logging:

```javascript
// In any API function
import { DefaultLogger } from 'adapt-auth-sdk';

const logger = new DefaultLogger();
logger.verbose = true;

// Pass logger to providers
const samlProvider = new SAMLProvider(config, logger);
```

This Gatsby integration provides a complete authentication solution optimized for localhost development and Netlify production deployment.

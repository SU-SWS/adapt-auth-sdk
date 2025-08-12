# ADAPT Auth SDK

A framework-agnostic TypeScript authentication library for ADAPT SAML integration. Designed for serverless, stateless environments with security-first defaults.

## Features

- **Framework Agnostic**: Works with Next.js, Express.js, and any Web API framework
- **TypeScript First**: Complete TypeScript implementation with strict typing
- **Security Focused**: HMAC-signed RelayState, encrypted sessions, CSRF protection
- **Serverless Ready**: Cookie-only sessions, no server-side storage required
- **Developer Friendly**: Simple API inspired by Auth.js patterns

## Quick Start

### Installation

```bash
npm install adapt-auth-sdk
```

### Basic Usage

```typescript
// lib/auth.ts
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
});
```

```typescript
// app/api/auth/login/route.ts
export async function GET(request: Request) {
  return auth.login(request);
}

// app/api/auth/acs/route.ts
export async function POST(request: Request) {
  return auth.handleCallback(request);
}

// app/api/auth/logout/route.ts
export async function POST(request: Request) {
  return auth.logout(request);
}
```

## Documentation

📚 **[Getting Started](./docs/getting-started.md)** - Installation and basic setup for Next.js and Express.js

⚙️ **[Configuration](./docs/configuration.md)** - Complete configuration reference and environment variables

🔒 **[Security](./docs/security.md)** - Security features, best practices, and threat protection

🚀 **[Advanced Usage](./docs/advanced-usage.md)** - Custom implementations, performance optimization, and advanced patterns

📖 **[API Reference](./docs/api-reference.md)** - Complete API documentation with examples

🔄 **[Migration Guide](./docs/migration.md)** - Migrating from v1.x and other authentication libraries

## Environment Variables

Set these required environment variables:

```bash
ADAPT_AUTH_SAML_ENTITY="your-saml-entity-id"
ADAPT_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----..."
ADAPT_AUTH_SAML_RETURN_ORIGIN="https://your-app.com"
ADAPT_AUTH_SESSION_SECRET="your-32-character-minimum-secret"
```

## Key Features

### Security First
- SAML 2.0 signature validation
- HMAC-signed RelayState tokens
- Encrypted cookie sessions
- CSRF protection

### Developer Experience
- TypeScript-first with strict typing
- Framework-agnostic design
- Simple, intuitive API
- Comprehensive error handling
- Detailed logging with automatic PII redaction

### Production Ready
- Serverless/stateless architecture
- Cookie-only sessions (no server storage)
- Comprehensive test coverage

## Quick Examples

### Getting User Session

```typescript
const session = await auth.getSession(request);
if (session) {
  console.log('User:', session.user.name);
}
```

### Protecting Routes

```typescript
// Next.js middleware
export async function middleware(request: NextRequest) {
  const session = await auth.getSession(request);
  if (!session && request.nextUrl.pathname.startsWith('/protected')) {
    return Response.redirect(new URL('/api/auth/login', request.url));
  }
}
```

### Custom Profile Mapping

```typescript
const auth = createAdaptNext({
  // ... config
  callbacks: {
    mapProfile: async (profile) => ({
      id: profile.encodedSUID,
      email: `${profile.userName}@stanford.edu`,
      name: `${profile.firstName} ${profile.lastName}`,
      department: profile.department,
    }),
  },
});
```

## License

GNU Version 3 License - see [LICENSE](./LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## Security

Security issues should be reported privately. Please do not open public GitHub issues for security vulnerabilities.

## Support

- 📖 [Documentation](./docs/)
- 🐛 [Issues](https://github.com/su-sws/adapt-auth-sdk/issues)
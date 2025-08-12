# Security

This document details the security features and best practices for the ADAPT Auth SDK.

## Security Architecture

The ADAPT Auth SDK implements multiple layers of security to protect against common authentication vulnerabilities:

### SAML Security

- **Signature Validation**: All SAML responses and assertions are cryptographically verified
- **Certificate Pinning**: IdP certificates are validated against configured values
- **Replay Protection**: InResponseTo validation prevents replay attacks
- **Time-based Validation**: NotBefore/NotOnOrAfter conditions enforced
- **Audience Validation**: Ensures responses are intended for your application

### Session Security

- **Encrypted Cookies**: All session data is encrypted using iron-session
- **CSRF Protection**: Built-in CSRF token generation and validation
- **Secure Cookie Flags**: HttpOnly, Secure, SameSite protections
- **Size Monitoring**: Prevents cookie overflow attacks

### RelayState Security

The RelayState mechanism is secured with HMAC signing:

```typescript
// RelayState contains:
{
  nonce: string,      // Cryptographically random value
  issuedAt: number,   // Timestamp for age validation
  returnTo?: string   // Optional redirect URL
}
// Signed with: HMAC-SHA256(payload, secret)
```

## Threat Protection

### Common Attack Vectors

#### SAML Response Tampering
**Protection**: Cryptographic signature validation of all SAML responses
```typescript
// Automatic validation in SAMLProvider
const validation = await this.strategy.validatePostResponse(body);
if (!validation.profile) {
  throw new Error('Invalid SAML response signature');
}
```

#### Session Hijacking
**Protection**: Encrypted session cookies with secure flags
```typescript
cookie: {
  httpOnly: true,    // Prevent XSS access
  secure: true,      // HTTPS only
  sameSite: 'lax',   // CSRF protection
}
```

#### CSRF Attacks
**Protection**: Built-in CSRF token generation and validation
```typescript
// Generate CSRF token
const csrfToken = AuthUtils.generateCSRFToken();

// Validate CSRF token
const isValid = AuthUtils.validateCSRFToken(token, session);
```

#### Replay Attacks
**Protection**: Timestamp validation and nonce verification
```typescript
// RelayState age validation
if (Date.now() - payload.issuedAt > maxAge * 1000) {
  throw new Error('RelayState expired');
}
```

#### Open Redirect
**Protection**: URL sanitization and same-origin enforcement
```typescript
// Sanitize return URLs
const sanitizedUrl = AuthUtils.sanitizeReturnUrl(url, allowedOrigins);
```

### Clock Skew Tolerance

SAML time-based validations include configurable clock skew tolerance:

```typescript
saml: {
  acceptedClockSkewMs: 60000, // 1 minute tolerance
}
```

## Data Protection

### Sensitive Data Handling

The SDK automatically redacts sensitive data from logs:

```typescript
// Automatic redaction in DefaultLogger
private redactSensitiveData(obj: any): any {
  const sensitiveKeys = [
    'password', 'secret', 'token', 'key', 'cert',
    'samlresponse', 'cookie', 'authorization'
  ];
  // ... redaction logic
}
```

### Cookie Security

#### Size Monitoring
```typescript
// Warns when cookies approach browser limits
if (cookieSize > this.config.cookieSizeThreshold) {
  this.logger.warn('Cookie size approaching limit', {
    size: cookieSize,
    threshold: this.config.cookieSizeThreshold
  });
}
```

#### Secure Flags
```typescript
// Production-ready cookie settings
const cookieOptions = {
  httpOnly: true,           // Prevent XSS
  secure: true,             // HTTPS only
  sameSite: 'lax' as const, // CSRF protection
  path: '/',                // Scope to entire app
};
```

### Certificate Management

Store IdP certificates securely:

```typescript
// Environment variable (recommended)
ADAPT_AUTH_SAML_CERT="-----BEGIN CERTIFICATE-----
MIIDBjCCAe4CCQDXo8b5...
-----END CERTIFICATE-----"

// Or configure programmatically
saml: {
  idpCert: process.env.IDP_CERTIFICATE,
}
```

## Security Best Practices

### 1. Use Strong Secrets

```bash
# Generate strong session secret (32+ characters)
ADAPT_AUTH_SESSION_SECRET="$(openssl rand -base64 32)"

# Generate RelayState secret
ADAPT_AUTH_RELAY_STATE_SECRET="$(openssl rand -base64 32)"
```

### 2. Configure HTTPS

```typescript
// Enforce HTTPS in production
saml: {
  returnToOrigin: 'https://your-app.com', // Never HTTP
}

session: {
  cookie: {
    secure: process.env.NODE_ENV === 'production',
  }
}
```

### 3. Validate Configuration

```typescript
// The SDK validates configuration at startup
try {
  const auth = createAdaptNext(config);
} catch (error) {
  console.error('Security configuration invalid:', error.message);
  process.exit(1);
}
```

### 4. Monitor Security Events

```typescript
callbacks: {
  signIn: async ({ user, profile }) => {
    // Log successful authentication
    await auditLog.info('Authentication successful', {
      userId: user.id,
      timestamp: new Date().toISOString(),
      sourceIP: req.ip,
    });
  },

  signOut: async ({ session }) => {
    // Log logout events
    await auditLog.info('User logged out', {
      userId: session.user.id,
      timestamp: new Date().toISOString(),
    });
  }
}
```

### 5. Handle Errors Securely

```typescript
// Don't expose sensitive error details to users
try {
  await auth.handleCallback(request);
} catch (error) {
  logger.error('Authentication failed', error);

  // Return generic error to user
  return new Response('Authentication failed', { status: 401 });
}
```

### 6. Regular Security Updates

- Keep dependencies updated
- Monitor security advisories
- Rotate secrets regularly
- Review access logs

## Compliance Considerations

### Stanford Requirements

- SAML 2.0 compliance for Stanford WebAuth
- Proper handling of Stanford user attributes
- Secure session management for university data

### General Compliance

- **GDPR**: Minimal data collection, secure processing
- **SOC 2**: Audit logging, access controls
- **FERPA**: Secure handling of educational records

## Security Monitoring

### Logging Security Events

```typescript
// Enable verbose logging in development
const auth = createAdaptNext({
  verbose: true, // Detailed security event logging
});
```

### Common Security Log Events

- Authentication attempts (success/failure)
- Session creation/destruction
- SAML response validation results
- RelayState validation failures
- Cookie size warnings
- Configuration validation errors

### Log Redaction

The SDK automatically redacts sensitive data:

```typescript
// Redacted in logs
{
  "message": "SAML response received",
  "samlResponse": "[REDACTED]",
  "user": { "id": "user123", "email": "[REDACTED]" }
}
```

## Incident Response

### Security Incident Checklist

1. **Identify the threat**
   - Review error logs and audit trails
   - Check for unusual authentication patterns

2. **Contain the incident**
   - Rotate session secrets if compromised
   - Invalidate active sessions if necessary

3. **Investigate**
   - Analyze SAML response integrity
   - Check for configuration tampering

4. **Recover**
   - Update certificates if needed
   - Apply security patches

5. **Lessons learned**
   - Update security procedures
   - Enhance monitoring

### Emergency Procedures

```typescript
// Emergency session invalidation
// Rotate the session secret to invalidate all sessions
ADAPT_AUTH_SESSION_SECRET="new-secret-generated-after-incident"

// Or programmatically clear cookies
response.setHeader('Set-Cookie',
  'adapt-auth-session=; Max-Age=0; Path=/; HttpOnly; Secure'
);
```

## Security Testing

### Recommended Tests

1. **Authentication Flow Security**
   - SAML response tampering
   - RelayState manipulation
   - Session hijacking attempts

2. **Cookie Security**
   - HttpOnly flag enforcement
   - Secure flag in production
   - Size limit validation

3. **CSRF Protection**
   - Token generation/validation
   - State parameter verification

4. **Input Validation**
   - Return URL sanitization
   - SAML attribute handling

## Reporting Security Issues

If you discover a security vulnerability:

1. **Do not** open a public GitHub issue
2. Email security concerns to the maintainers
3. Include reproduction steps and impact assessment
4. Allow time for investigation and patching

The security of the ADAPT Auth SDK is a top priority, and we appreciate responsible disclosure of potential vulnerabilities.

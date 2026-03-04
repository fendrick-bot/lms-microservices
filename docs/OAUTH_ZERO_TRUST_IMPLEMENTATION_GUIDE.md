# OAuth 2.0 / OIDC & Zero-Trust Implementation Guide

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Authentication Flows](#authentication-flows)
3. [Zero-Trust Security Model](#zero-trust-security-model)
4. [File Structure & Responsibilities](#file-structure--responsibilities)
5. [Code Examples](#code-examples)
6. [API Reference](#api-reference)
7. [Configuration Guide](#configuration-guide)

---

## Architecture Overview

### System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                              AUTHENTICATION ARCHITECTURE                                 │
└─────────────────────────────────────────────────────────────────────────────────────────┘

                                    ┌─────────────┐
                                    │    USER     │
                                    │   (Browser) │
                                    └──────┬──────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    │                      │                      │
                    ▼                      ▼                      ▼
           ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
           │  OAuth 2.0      │   │  Zero-Trust     │   │  Direct API     │
           │  Authorization  │   │  Gateway        │   │  (Service Auth) │
           │  Code Flow      │   │  (Verify All)   │   │  (HMAC + API Key│
           └────────┬────────┘   └────────┬────────┘   └────────┬────────┘
                    │                      │                      │
                    └──────────────────────┼──────────────────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │    API Gateway         │
                              │    (Kong/Nginx)        │
                              └───────────┬────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
           ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
           │User Service │      │Course Service      │Payment Service
           │(OAuth Server│      │(Resource   │      │(Resource   │
           │+ Zero-Trust)│      │   Server)   │      │   Server)   │
           └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
                  │                    │                    │
                  ▼                    ▼                    ▼
           ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
           │  PostgreSQL │      │  PostgreSQL │      │  PostgreSQL │
           │  (Users +   │      │  (Courses + │      │  (Payments +│
           │   OAuth)    │      │   Enroll)   │      │   Trans)    │
           └─────────────┘      └─────────────┘      └─────────────┘
                  │                    │                    │
                  └────────────────────┼────────────────────┘
                                       │
                                       ▼
                              ┌─────────────────┐
                              │     Redis       │
                              │  (Token Cache + │
                              │   Sessions +    │
                              │   Rate Limit)   │
                              └─────────────────┘
```

### Component Interaction Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                         REQUEST LIFECYCLE FLOW                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘

User Login Flow:
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  User   │────▶│  OAuth      │────▶│  User       │────▶│  Issue      │────▶│  Return     │
│  Login  │     │  Authorize  │     │  Verify     │     │  Tokens     │     │  Tokens     │
└─────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                     │                      │                    │
                     ▼                      ▼                    ▼
               ┌──────────┐          ┌──────────┐         ┌──────────┐
               │  PKCE    │          │ Password │         │  Access  │
               │  Code    │          │  Check   │         │  + ID    │
               │Verifier  │          │          │         │  Token   │
               └──────────┘          └──────────┘         └──────────┘

API Request Flow (Zero-Trust):
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  API    │────▶│   Extract   │────▶│  Introspect │────▶│   Verify    │────▶│  Calculate  │
│ Request │     │   Token     │     │   Token     │     │   Redis     │     │ Trust Score │
└─────────┘     └─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                                                                                    │
                     ┌──────────────────────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Access    │◀────│   Check     │◀────│   Validate  │◀────│   Device    │
│   Granted   │     │   Score     │     │   Session   │     │Fingerprint  │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Score < 50 │────▶ DENY
                    │  Score < 60 │────▶ STEP-UP MFA
                    │  Score < 30 │────▶ RE-AUTH
                    └─────────────┘
```

---

## Authentication Flows

### 1. OAuth 2.0 Authorization Code Flow with PKCE

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    AUTHORIZATION CODE FLOW WITH PKCE                                     │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Step 1: Generate PKCE Parameters (Client Side)
┌─────────────────────────────────────────────────────────────────┐
│  Client generates:                                               │
│  • code_verifier = random(32 bytes)                             │
│  • code_challenge = SHA256(code_verifier)                       │
│  • state = random(16 bytes)                                     │
└─────────────────────────────────────────────────────────────────┘

Step 2: Authorization Request
┌─────────┐                                          ┌─────────────┐
│  Client │──────────────────────────────────────────▶│OAuth Server │
│         │  GET /oauth/authorize                     │             │
│         │  ?response_type=code                      │             │
│         │  &client_id=lms-web-client                │             │
│         │  &redirect_uri=https://app.lms.local/callback│          │
│         │  &scope=openid profile email courses:read │             │
│         │  &state=xyz123                            │             │
│         │  &code_challenge=abc456...                │             │
│         │  &code_challenge_method=S256              │             │
└─────────┘                                          └─────────────┘

Step 3: User Authentication (if not logged in)
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│OAuth Server │────▶│  Redirect   │────▶│  Login Page │
│             │     │  to /login  │     │             │
└─────────────┘     └─────────────┘     └─────────────┘

Step 4: Authorization Grant
┌─────────────┐                                          ┌─────────┐
│OAuth Server │──────────────────────────────────────────▶│ Client  │
│             │  302 Redirect                             │         │
│             │  Location: https://app.lms.local/callback │         │
│             │  ?code=authz_code_xyz                     │         │
│             │  &state=xyz123                            │         │
└─────────────┘                                          └─────────┘

Step 5: Token Exchange
┌─────────┐                                          ┌─────────────┐
│  Client │──────────────────────────────────────────▶│OAuth Server │
│         │  POST /oauth/token                        │             │
│         │  Content-Type: application/x-www-form-urlencoded         │
│         │                                           │             │
│         │  grant_type=authorization_code            │             │
│         │  &code=authz_code_xyz                     │             │
│         │  &redirect_uri=https://app.lms.local/callback            │
│         │  &client_id=lms-web-client                │             │
│         │  &client_secret=secret123                 │             │
│         │  &code_verifier=original_verifier         │             │
└─────────┘                                          └─────────────┘

Step 6: Token Response
┌─────────────┐                                          ┌─────────┐
│OAuth Server │──────────────────────────────────────────▶│  Client │
│             │  200 OK                                   │         │
│             │  Content-Type: application/json           │         │
│             │                                           │         │
│             │  {                                        │         │
│             │    "access_token": "eyJhbG...",            │         │
│             │    "token_type": "Bearer",                │         │
│             │    "expires_in": 3600,                    │         │
│             │    "refresh_token": "dGhpcyBpcyBh...",     │         │
│             │    "scope": "openid profile email",       │         │
│             │    "id_token": "eyJhbGciOiJSUzI1NiIs..."  │         │
│             │  }                                        │         │
└─────────────┘                                          └─────────┘
```

### 2. Zero-Trust Request Verification Flow

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                      ZERO-TRUST VERIFICATION SEQUENCE                                    │
└─────────────────────────────────────────────────────────────────────────────────────────┘

Incoming Request
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 1. TOKEN EXTRACTION                                              │
│    • Check Authorization: Bearer <token> header                 │
│    • Fallback: Cookie (access_token=value)                      │
│    • Result: token string or 401 Unauthorized                   │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. TOKEN INTROSPECTION (Verify Every Request)                    │
│    • POST /oauth/introspect                                     │
│    • Check if token is active                                   │
│    • Get user info, scopes, expiration                          │
│    • Cache result for 30 seconds                                │
│    • Result: introspection data or 401                          │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. REDIS BLACKLIST CHECK                                         │
│    • Check if token is revoked                                  │
│    • Key: token:revoked:<hash>                                  │
│    • Result: 401 if revoked                                     │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. DEVICE FINGERPRINTING                                         │
│    • Hash: user-agent + accept-language + encoding + IP         │
│    • Store/Compare with previous context                        │
│    • Risk factor if NEW_DEVICE detected                         │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. TRUST SCORE CALCULATION                                       │
│    • Start: 100 points                                          │
│    • -20: New device                                            │
│    • -15: New location (IP)                                     │
│    • -30: Suspicious IP (in blocklist)                          │
│    • -15: Rapid requests (>100/min)                             │
│    • -10: Unusual time (3 AM)                                   │
│    • Result: 0-100 score                                        │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. TRUST SCORE EVALUATION                                        │
│    • Score >= 60: Access Granted                                │
│    • Score 30-59: Step-Up Auth Required (MFA)                   │
│    • Score < 30:  Re-authentication Required                    │
│    • Score < 50:  Access Denied (suspicious)                    │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 7. CONTINUOUS VALIDATION                                         │
│    • Check last verified timestamp                              │
│    • If > 15 minutes: Re-verify device fingerprint              │
│    • If changed: Force re-auth                                  │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. LEAST PRIVILEGE CHECK                                         │
│    • Verify required scope(s) present                           │
│    • Check RBAC permissions                                     │
│    • Cache permission result (60 sec)                           │
│    • Result: 403 if insufficient                                │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. AUDIT LOGGING                                                 │
│    • Log access attempt (success/failure)                       │
│    • Include: user, IP, trust score, risk factors               │
│    • Alert on suspicious activity                               │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│ 10. RESPONSE HEADERS                                             │
│    • X-Trust-Score: 85                                          │
│    • X-Session-ID: session_abc123                               │
│    • Security headers (HSTS, CSP, etc.)                         │
└─────────────────────────────────────────────────────────────────┘
       │
       ▼
  ACCESS GRANTED
```

---

## Zero-Trust Security Model

### Trust Score Calculation

```typescript
// Trust Score Algorithm
function calculateTrustScore(context: TrustContext): number {
  let score = 100;
  const riskFactors: RiskFactor[] = [];

  // Device Analysis
  if (isNewDevice(context.deviceFingerprint, context.userId)) {
    score -= 20;
    riskFactors.push({
      type: RiskFactorType.NEW_DEVICE,
      severity: 'medium',
      description: 'First time login from this device'
    });
  }

  // Location Analysis
  if (isNewLocation(context.ipAddress, context.userId)) {
    score -= 15;
    riskFactors.push({
      type: RiskFactorType.NEW_LOCATION,
      severity: 'low',
      description: 'Login from new IP address'
    });
  }

  // IP Reputation
  if (isSuspiciousIP(context.ipAddress)) {
    score -= 30;
    riskFactors.push({
      type: RiskFactorType.SUSPICIOUS_IP,
      severity: 'high',
      description: 'IP flagged in threat intelligence'
    });
  }

  // Behavioral Analysis
  if (isRapidRequestPattern(context.userId)) {
    score -= 15;
    riskFactors.push({
      type: RiskFactorType.RAPID_REQUESTS,
      severity: 'medium',
      description: 'Unusually high request rate'
    });
  }

  // Time Analysis
  if (isUnusualHour(context.timestamp)) {
    score -= 10;
    riskFactors.push({
      type: RiskFactorType.UNUSUAL_TIME,
      severity: 'low',
      description: 'Login at unusual hour (3 AM)'
    });
  }

  return Math.max(0, score);
}

// Decision Matrix
const decisionMatrix = {
  score >= 80: { action: 'ALLOW', mfa: false },
  score >= 60: { action: 'ALLOW', mfa: false },
  score >= 50: { action: 'ALLOW', mfa: true },  // Step-up auth
  score >= 30: { action: 'STEP_UP', mfa: true }, // Require MFA
  score < 30:  { action: 'REAUTH', mfa: true },  // Force re-login
  score < 50 && riskFactors.length > 2: { action: 'DENY' }
};
```

---

## File Structure & Responsibilities

### User Service (OAuth Server + Zero-Trust)

```
services/user-service/src/
│
├── oauth/
│   └── oauth-server.ts          # OAuth 2.0 / OIDC implementation
│                                  • Authorization endpoint
│                                  • Token endpoint
│                                  • UserInfo endpoint
│                                  • Revocation & Introspection
│
├── middleware/
│   ├── rate-limit.middleware.ts # Rate limiting strategies
│   │                              • Login: 5/15min
│   │                              • Token: 20/5min
│   │                              • OAuth: 10/10min
│   │
│   └── zero-trust.middleware.ts # Zero-Trust verification
│                                  • Trust score calculation
│                                  • Device fingerprinting
│                                  • Continuous validation
│
├── services/
│   ├── redis.service.ts         # Redis operations
│   │                              • Token blacklist
│   │                              • Session management
│   │                              • Rate limiting
│   │
│   └── audit.service.ts         # Security audit logging
│                                  • Event buffering
│                                  • Brute force detection
│
├── routes/
│   └── oauth.routes.ts          # OAuth route definitions
│
└── utils/
    └── jwt.utils.ts             # JWT + OIDC ID Token utilities
```

### Shared Auth Library (@lms/shared-auth)

```
libs/shared-auth/src/
│
├── oauth/
│   ├── oauth-client.ts          # OAuth client for services
│   │                              • Authorization code flow
│   │                              • Client credentials
│   │                              • Token refresh
│   │
│   ├── token-introspector.ts    # Token validation
│   │                              • Introspection endpoint
│   │                              • Caching layer
│   │
│   └── oauth.middleware.ts      # OAuth auth middleware
│                                  • Token extraction
│                                  • Scope validation
│
├── zero-trust/
│   └── zero-trust.middleware.ts # Zero-Trust for services
│                                  • Trust scoring
│                                  • Risk assessment
│
├── cache/
│   └── redis-cache.ts           # Redis cache utilities
│                                  • Token caching
│                                  • Permission caching
│
├── types.ts                     # TypeScript definitions
│
├── auth-client.ts               # Legacy auth client
│
└── middleware/
    └── auth.middleware.ts       # Legacy auth middleware
```

### Database Schema

```
libs/database/src/schemas/
│
└── oauth.ts                     # OAuth tables
    • oauth_clients              # Registered applications
    • authorization_codes        # PKCE auth codes
    • refresh_tokens             # With rotation
    • access_token_blacklist     # Revoked tokens
    • audit_logs                 # Security events
```

---

## Code Examples

### Example 1: OAuth Client Usage (Web Application)

```typescript
// client/src/auth/oauth-client.ts
import { OAuthClient } from '@lms/shared-auth';

const oauthClient = new OAuthClient({
  issuer: 'https://auth.lms.local',
  authorizationEndpoint: 'https://auth.lms.local/oauth/authorize',
  tokenEndpoint: 'https://auth.lms.local/oauth/token',
  userInfoEndpoint: 'https://auth.lms.local/oauth/userinfo',
  revocationEndpoint: 'https://auth.lms.local/oauth/revoke',
  clientId: 'lms-web-client',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://app.lms.local/callback',
  scope: 'openid profile email courses:read',
});

// Step 1: Redirect to authorization
function login() {
  // Generate PKCE
  const { codeVerifier, codeChallenge } = OAuthClient.generatePKCE();
  const state = OAuthClient.generateState();
  
  // Store for later
  sessionStorage.setItem('code_verifier', codeVerifier);
  sessionStorage.setItem('state', state);
  
  // Build URL
  const authUrl = oauthClient.buildAuthorizationUrl(
    state,
    codeChallenge,
    OAuthClient.generateNonce()
  );
  
  window.location.href = authUrl;
}

// Step 2: Handle callback
async function handleCallback(code: string, state: string) {
  // Verify state
  const storedState = sessionStorage.getItem('state');
  if (state !== storedState) {
    throw new Error('Invalid state parameter');
  }
  
  // Exchange code for tokens
  const codeVerifier = sessionStorage.getItem('code_verifier')!;
  const tokens = await oauthClient.exchangeCode(code, codeVerifier);
  
  // Store tokens securely
  sessionStorage.setItem('access_token', tokens.access_token);
  sessionStorage.setItem('refresh_token', tokens.refresh_token);
  
  // Get user info
  const userInfo = await oauthClient.getUserInfo(tokens.access_token);
  
  return userInfo;
}

// Step 3: Refresh token
async function refreshAccessToken() {
  const refreshToken = sessionStorage.getItem('refresh_token');
  if (!refreshToken) {
    throw new Error('No refresh token');
  }
  
  const tokens = await oauthClient.refreshToken(refreshToken);
  sessionStorage.setItem('access_token', tokens.access_token);
  
  return tokens.access_token;
}

// Step 4: Logout
async function logout() {
  const accessToken = sessionStorage.getItem('access_token');
  
  if (accessToken) {
    await oauthClient.revokeToken(accessToken, 'access_token');
  }
  
  sessionStorage.clear();
  window.location.href = '/';
}
```

### Example 2: Zero-Trust Protected Route (Course Service)

```typescript
// services/course-service/src/routes/course.routes.ts
import { Router } from 'express';
import { 
  createZeroTrustMiddleware, 
  requireScope,
  RedisCache,
  TokenIntrospector 
} from '@lms/shared-auth';

const router = Router();

// Initialize Zero-Trust components
const cache = new RedisCache({
  host: process.env.REDIS_HOST || 'localhost',
  port: parseInt(process.env.REDIS_PORT || '6379'),
});

const introspector = new TokenIntrospector({
  introspectionEndpoint: 'https://auth.lms.local/oauth/introspect',
  clientId: 'course-service',
  clientSecret: process.env.COURSE_SERVICE_API_KEY!,
});

const zeroTrust = createZeroTrustMiddleware(introspector, cache, {
  minTrustScore: 50,
  reauthThreshold: 30,
  stepUpThreshold: 60,
});

// Public route - no auth required
router.get('/public/courses', getPublicCourses);

// Protected route - requires valid token + trust score
router.get(
  '/courses',
  zeroTrust,                                    // Zero-Trust verification
  requireScope('courses:read', 'openid'),      // Least privilege
  getCourses
);

// Admin route - requires high trust + admin scope
router.post(
  '/courses',
  zeroTrust,
  requireScope('courses:write', 'admin'),
  requireRole('teacher', 'super_admin'),
  createCourse
);

// High-security route - requires step-up auth
router.delete(
  '/courses/:id',
  zeroTrust,
  requireScope('courses:delete', 'admin'),
  requireTrustScore(70),  // Custom middleware for high-value operations
  deleteCourse
);

export default router;
```

### Example 3: Custom Zero-Trust Middleware

```typescript
// Custom middleware for high-value operations
function requireTrustScore(minScore: number) {
  return (req: ZeroTrustRequest, res: Response, next: NextFunction) => {
    const trustScore = req.user?.trustScore || 0;
    
    if (trustScore < minScore) {
      return res.status(403).json({
        error: 'insufficient_trust',
        message: `Trust score ${trustScore} below required ${minScore}`,
        action: 'verify_identity',
      });
    }
    
    next();
  };
}

// Middleware to check for suspicious patterns
function fraudDetection(req: ZeroTrustRequest, res: Response, next: NextFunction) {
  const context = req.trustContext;
  
  // Check for velocity attack
  if (context?.riskFactors.some(rf => rf.type === RiskFactorType.RAPID_REQUESTS)) {
    // Add CAPTCHA challenge or delay
    return res.status(429).json({
      error: 'suspicious_activity',
      message: 'Please complete CAPTCHA to continue',
      captchaRequired: true,
    });
  }
  
  // Check for impossible travel
  const lastLocation = await getLastLocation(req.user!.id);
  if (lastLocation && isImpossibleTravel(lastLocation, context!.ipAddress)) {
    await alertSecurityTeam(req.user!.id, 'impossible_travel');
  }
  
  next();
}
```

### Example 4: Service-to-Service Authentication

```typescript
// Service client with client credentials flow
import { OAuthClient } from '@lms/shared-auth';

class CourseServiceClient {
  private oauthClient: OAuthClient;
  private accessToken: string | null = null;
  private tokenExpiry: number = 0;

  constructor() {
    this.oauthClient = new OAuthClient({
      issuer: 'https://auth.lms.local',
      tokenEndpoint: 'https://auth.lms.local/oauth/token',
      clientId: 'course-service',
      clientSecret: process.env.COURSE_SERVICE_API_KEY!,
      scope: 'internal:enrollments internal:courses',
    });
  }

  private async getToken(): Promise<string> {
    // Check if token is still valid
    if (this.accessToken && Date.now() < this.tokenExpiry - 60000) {
      return this.accessToken;
    }

    // Get new token using client credentials
    const tokens = await this.oauthClient.getClientCredentialsToken();
    
    this.accessToken = tokens.access_token;
    this.tokenExpiry = Date.now() + tokens.expires_in * 1000;
    
    return this.accessToken;
  }

  async completeEnrollment(userId: string, courseId: string): Promise<any> {
    const token = await this.getToken();
    
    const response = await fetch(
      'https://course-service.internal/api/enrollments/complete',
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          'X-Service-ID': 'payment-service',
        },
        body: JSON.stringify({ userId, courseId }),
      }
    );

    if (!response.ok) {
      throw new Error(`Enrollment failed: ${response.statusText}`);
    }

    return response.json();
  }
}
```

---

## API Reference

### OAuth 2.0 Endpoints

| Endpoint | Method | Description | Auth Required |
|----------|--------|-------------|---------------|
| `/.well-known/openid-configuration` | GET | OIDC Discovery | No |
| `/oauth/jwks` | GET | JSON Web Key Set | No |
| `/oauth/authorize` | GET | Authorization endpoint | No (user auth) |
| `/oauth/token` | POST | Token endpoint | Client credentials |
| `/oauth/userinfo` | GET/POST | UserInfo endpoint | Bearer token |
| `/oauth/revoke` | POST | Token revocation | Client credentials |
| `/oauth/introspect` | POST | Token introspection | Client credentials |

### Request/Response Examples

#### Token Request
```bash
curl -X POST https://auth.lms.local/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE" \
  -d "redirect_uri=https://app.lms.local/callback" \
  -d "client_id=lms-web-client" \
  -d "client_secret=SECRET" \
  -d "code_verifier=PKCE_VERIFIER"
```

#### Token Response
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "dGhpcyBpcyBhIHJlZnJlc2ggdG9rZW4...",
  "scope": "openid profile email courses:read",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ..."
}
```

#### Token Introspection Request
```bash
curl -X POST https://auth.lms.local/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN" \
  -d "client_id=course-service" \
  -d "client_secret=SERVICE_SECRET"
```

#### Token Introspection Response
```json
{
  "active": true,
  "scope": "openid profile courses:read",
  "client_id": "lms-web-client",
  "username": "student@example.com",
  "token_type": "Bearer",
  "exp": 1704067200,
  "iat": 1704063600,
  "sub": "user-uuid-123",
  "aud": "lms-web-client",
  "iss": "https://auth.lms.local"
}
```

---

## Configuration Guide

### Environment Variables

```bash
# User Service (.env)

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/lms_db

# Redis
REDIS_URL=redis://localhost:6379

# OAuth/OIDC
OAUTH_ISSUER=https://auth.lms.local
JWT_SECRET=your-jwt-secret-min-32-chars
JWT_EXPIRES_IN=3600
JWT_REFRESH_EXPIRES_IN=604800

# RSA Keys for OIDC (Base64 encoded)
OIDC_PRIVATE_KEY=LS0tLS1CRUdJTiB...  # openssl genrsa 2048 | base64
OIDC_PUBLIC_KEY=LS0tLS1CRUdJTiB...   # openssl rsa -in key.pem -pubout | base64

# Service API Keys
USER_SERVICE_API_KEY=user_service_key_$(openssl rand -hex 16)
COURSE_SERVICE_API_KEY=course_service_key_$(openssl rand -hex 16)
PAYMENT_SERVICE_API_KEY=payment_service_key_$(openssl rand -hex 16)
# ... etc for all services

# Rate Limiting
RATE_LIMIT_LOGIN_MAX=5
RATE_LIMIT_LOGIN_WINDOW=900000  # 15 minutes
RATE_LIMIT_TOKEN_MAX=20
RATE_LIMIT_TOKEN_WINDOW=300000  # 5 minutes
```

### Database Migration

```typescript
// Run migrations for OAuth tables
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { db, pool } from '@lms/database';

async function runMigrations() {
  await migrate(db, { migrationsFolder: './drizzle' });
  await pool.end();
}

runMigrations();
```

### Registering an OAuth Client

```sql
-- Insert a new OAuth client
INSERT INTO oauth_clients (
  client_id,
  client_secret,
  client_name,
  client_description,
  redirect_uris,
  allowed_scopes,
  grant_types,
  response_types,
  is_confidential,
  is_active
) VALUES (
  'lms-web-client',
  'your-secure-client-secret',
  'LMS Web Application',
  'Main LMS web application',
  '["https://app.lms.local/callback", "https://app.lms.local/silent-callback"]',
  '["openid", "profile", "email", "courses:read", "courses:write", "payments"]',
  '["authorization_code", "refresh_token"]',
  '["code"]',
  true,
  true
);
```

---

## Security Best Practices

1. **Always use PKCE** for public clients (SPAs, mobile apps)
2. **Rotate refresh tokens** on every use
3. **Use short-lived access tokens** (1 hour max)
4. **Verify every request** with token introspection
5. **Monitor trust scores** and alert on anomalies
6. **Log all security events** to audit trail
7. **Use Redis for token blacklist** with automatic expiration
8. **Implement rate limiting** on all auth endpoints
9. **Use HTTPS everywhere** with HSTS headers
10. **Store secrets securely** (AWS Secrets Manager, Vault)

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Invalid client" | Wrong client_id/secret | Verify credentials in database |
| "Invalid code_verifier" | PKCE mismatch | Ensure code_challenge = SHA256(verifier) |
| "Token inactive" | Token revoked or expired | Check Redis blacklist; refresh token |
| "Rate limit exceeded" | Too many requests | Wait for window to reset; check limits |
| "Trust score too low" | Risk factors detected | Review risk factors; complete MFA |
| "Insufficient scope" | Missing permissions | Request additional scopes at auth time |

### Debug Mode

```typescript
// Enable debug logging
process.env.DEBUG_OAUTH = 'true';
process.env.DEBUG_ZERO_TRUST = 'true';

// Check trust context
app.use((req, res, next) => {
  console.log('Trust Context:', req.trustContext);
  console.log('User:', req.user);
  next();
});
```

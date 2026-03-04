# Authentication Testing Guide

This guide covers how to test the OAuth/OIDC authentication flow and service-to-service authentication in the LMS backend.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [OAuth/OIDC Flow Testing](#oauthoidc-flow-testing)
4. [Service-to-Service Authentication Testing](#service-to-service-authentication-testing)
5. [Manual Testing with cURL](#manual-testing-with-curl)
6. [Integration Testing](#integration-testing)

---

## Prerequisites

1. **Start the required services:**
   ```bash
   # Start User Service (port 3001)
   cd services/user-service
   npm run dev
   
   # Start Course Service (port 3002) - for service-to-service tests
   cd services/course-service
   npm run dev
   
   # Start API Gateway (port 3000) - optional
   cd services/api-gateway
   npm run dev
   ```

2. **Environment Variables** (should be in `.env`):
   ```bash
   # Copy from .env.auth
   COURSE_SERVICE_API_KEY=course-service_g7qMhbliy1fiMCStqr6HJ7OQ
   PAYMENT_SERVICE_API_KEY=payment-service_QgECslp9mZS2EyZkDSS1kT6I
   SERVICE_SECRET_KEY=xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ
   USER_SERVICE_URL=http://localhost:3001
   ```

---

## Quick Start

Run the automated test scripts:

```bash
# Windows PowerShell
.\scripts\test-oauth-flow.ps1

# Linux/Mac/Git Bash
chmod +x scripts/test-oauth-flow.sh
./scripts/test-oauth-flow.sh
```

---

## OAuth/OIDC Flow Testing

### 1. OIDC Discovery Endpoint

Tests the OpenID Connect discovery configuration:

```bash
curl http://localhost:3001/.well-known/openid-configuration
```

**Expected Response:**
```json
{
  "issuer": "https://auth.lms.local",
  "authorization_endpoint": "https://auth.lms.local/oauth/authorize",
  "token_endpoint": "https://auth.lms.local/oauth/token",
  "userinfo_endpoint": "https://auth.lms.local/oauth/userinfo",
  "revocation_endpoint": "https://auth.lms.local/oauth/revoke",
  "introspection_endpoint": "https://auth.lms.local/oauth/introspect",
  ...
}
```

### 2. Client Credentials Flow (Service-to-Service)

Used for machine-to-machine authentication:

```bash
curl -X POST http://localhost:3001/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=course-service" \
  -d "client_secret=course-service_g7qMhbliy1fiMCStqr6HJ7OQ" \
  -d "scope=courses:read courses:write"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "courses:read courses:write"
}
```

### 3. Token Introspection (RFC 7662)

Check if a token is active and get its metadata:

```bash
curl -X POST http://localhost:3001/oauth/introspect \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type_hint": "access_token"
  }'
```

**Expected Response (Active Token):**
```json
{
  "active": true,
  "scope": "courses:read courses:write",
  "client_id": "course-service",
  "token_type": "Bearer",
  "exp": 1704067200,
  "iat": 1704063600,
  "sub": "client:course-service",
  "aud": "course-service",
  "iss": "https://auth.lms.local"
}
```

### 4. Token Revocation (RFC 7009)

Revoke an access or refresh token:

```bash
curl -X POST http://localhost:3001/oauth/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type_hint": "access_token"
  }'
```

**Expected Response:**
```json
{}
```

### 5. Authorization Code Flow (with PKCE)

For user authentication (requires browser interaction):

**Step 1:** Generate PKCE parameters
```bash
# Generate code_verifier (random string)
code_verifier=$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-43)

# Generate code_challenge (SHA256 hash of verifier, base64url encoded)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=+/' | tr '+/' '-_')

echo "Code Verifier: $code_verifier"
echo "Code Challenge: $code_challenge"
```

**Step 2:** Open browser for authorization (manual step)
```
http://localhost:3001/oauth/authorize?
  response_type=code&
  client_id=your-client-id&
  redirect_uri=http://localhost:3000/callback&
  scope=openid profile email&
  state=random-state-value&
  code_challenge=YOUR_CODE_CHALLENGE&
  code_challenge_method=S256
```

**Step 3:** Exchange code for tokens
```bash
curl -X POST http://localhost:3001/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=your-client-id" \
  -d "client_secret=your-client-secret" \
  -d "code=AUTHORIZATION_CODE_FROM_CALLBACK" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=YOUR_CODE_VERIFIER"
```

---

## Service-to-Service Authentication Testing

### Understanding the HMAC Authentication

Service-to-service requests use HMAC-SHA256 signatures for security:

```
Headers Required:
- x-service-api-key: Service's API key
- x-service-id: Service identifier (e.g., "course-service")
- x-timestamp: Unix timestamp in milliseconds
- x-signature: HMAC-SHA256 signature

Signature Generation:
payload = "{serviceId}:{timestamp}:{jsonBody}"
signature = HMAC-SHA256(payload, SERVICE_SECRET_KEY)
```

### Test Service-to-Service Authentication

#### Using the AuthClient (Recommended)

```typescript
import { createAuthClient } from '@lms/shared-auth';

const authClient = createAuthClient('course-service');

// This automatically adds HMAC headers
const result = await authClient.verifyToken('user-jwt-token');
console.log(result);
```

#### Manual cURL Test

```bash
# Set variables
SERVICE_ID="course-service"
API_KEY="course-service_g7qMhbliy1fiMCStqr6HJ7OQ"
SECRET_KEY="xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ"
TIMESTAMP=$(date +%s000)
BODY='{"token":"test-token-to-verify"}'

# Generate HMAC signature
PAYLOAD="$SERVICE_ID:$TIMESTAMP:$BODY"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET_KEY" | sed 's/^.* //')

# Make request
curl -X POST http://localhost:3001/api/auth-verification/verify-token \
  -H "Content-Type: application/json" \
  -H "x-service-api-key: $API_KEY" \
  -H "x-service-id: $SERVICE_ID" \
  -H "x-timestamp: $TIMESTAMP" \
  -H "x-signature: $SIGNATURE" \
  -d "$BODY"
```

#### Using Node.js Script

```typescript
import crypto from 'crypto';
import axios from 'axios';

const SERVICE_ID = 'course-service';
const API_KEY = 'course-service_g7qMhbliy1fiMCStqr6HJ7OQ';
const SECRET_KEY = 'xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ';

async function makeAuthenticatedRequest(endpoint: string, data: any) {
  const timestamp = Date.now().toString();
  const payload = `${SERVICE_ID}:${timestamp}:${JSON.stringify(data)}`;
  
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(payload)
    .digest('hex');
  
  const response = await axios.post(
    `http://localhost:3001${endpoint}`,
    data,
    {
      headers: {
        'x-service-api-key': API_KEY,
        'x-service-id': SERVICE_ID,
        'x-timestamp': timestamp,
        'x-signature': signature,
        'Content-Type': 'application/json',
      },
    }
  );
  
  return response.data;
}

// Test the authentication
makeAuthenticatedRequest('/api/auth-verification/verify-token', {
  token: 'test-jwt-token'
})
  .then(result => console.log('Success:', result))
  .catch(error => console.error('Error:', error.response?.data || error.message));
```

---

## Manual Testing with cURL

### Complete Test Sequence

```bash
#!/bin/bash

BASE_URL="http://localhost:3001"

# 1. Test OIDC Discovery
echo "=== 1. OIDC Discovery ==="
curl -s "$BASE_URL/.well-known/openid-configuration" | jq .

# 2. Get Service Token (Client Credentials)
echo -e "\n=== 2. Client Credentials Token ==="
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=course-service" \
  -d "client_secret=course-service_g7qMhbliy1fiMCStqr6HJ7OQ" \
  -d "scope=courses:read")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
echo "Token: ${ACCESS_TOKEN:0:50}..."

# 3. Introspect Token
echo -e "\n=== 3. Token Introspection ==="
curl -s -X POST "$BASE_URL/oauth/introspect" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$ACCESS_TOKEN\",\"token_type_hint\":\"access_token\"}" | jq .

# 4. Test Service-to-Service Auth
echo -e "\n=== 4. Service-to-Service HMAC Auth ==="
TIMESTAMP=$(date +%s000)
SERVICE_ID="course-service"
API_KEY="course-service_g7qMhbliy1fiMCStqr6HJ7OQ"
SECRET_KEY="xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ"
BODY='{"token":"test"}'
PAYLOAD="$SERVICE_ID:$TIMESTAMP:$BODY"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET_KEY" | sed 's/^.* //')

curl -s -X POST "$BASE_URL/api/auth-verification/verify-token" \
  -H "Content-Type: application/json" \
  -H "x-service-api-key: $API_KEY" \
  -H "x-service-id: $SERVICE_ID" \
  -H "x-timestamp: $TIMESTAMP" \
  -H "x-signature: $SIGNATURE" \
  -d "$BODY" | jq .

# 5. Revoke Token
echo -e "\n=== 5. Token Revocation ==="
curl -s -X POST "$BASE_URL/oauth/revoke" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"$ACCESS_TOKEN\",\"token_type_hint\":\"access_token\"}" | jq .
```

---

## Integration Testing

### Testing from Course Service to User Service

The Course Service uses the `AuthClient` from `@lms/shared-auth` to communicate with the User Service:

```typescript
// In Course Service - src/services/enrollment.service.ts
import { createAuthClient } from '@lms/shared-auth';

const authClient = createAuthClient('course-service');

// Verify a user's token
async function verifyUserToken(token: string) {
  try {
    const result = await authClient.verifyToken(token);
    return result.user;
  } catch (error) {
    throw new Error('Invalid token');
  }
}

// Check user permissions
async function checkUserPermission(userId: string, resource: string, action: string) {
  const result = await authClient.checkPermissions(userId, resource, action);
  return result.hasPermission;
}
```

### End-to-End Flow Test

1. **User logs in via API Gateway:**
   ```bash
   curl -X POST http://localhost:3000/api/user/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"student@example.com","password":"password"}'
   ```

2. **User accesses protected course endpoint:**
   ```bash
   curl -X GET http://localhost:3000/api/course/courses \
     -H "Authorization: Bearer USER_JWT_TOKEN"
   ```

3. **Course Service internally verifies token with User Service:**
   - Course Service extracts token from `Authorization` header
   - Uses `AuthClient` to call User Service's `/api/auth-verification/verify-token`
   - HMAC headers are automatically added by AuthClient
   - User Service validates HMAC and responds with user data

4. **Service-to-Service call (e.g., Payment → Course for enrollment):**
   ```bash
   # Payment Service calls Course Service internally
   curl -X POST http://localhost:3002/api/enrollments/internal/complete \
     -H "x-service-api-key: payment-service_QgECslp9mZS2EyZkDSS1kT6I" \
     -H "x-service-id: payment-service" \
     -H "x-timestamp: 1704067200000" \
     -H "x-signature: abc123..." \
     -d '{"userId":"uuid","courseId":"uuid"}'
   ```

---

## Troubleshooting

### Common Issues

1. **"Service authentication required" (401)**
   - Check that all required headers are present
   - Verify `x-service-api-key` matches the expected value in User Service

2. **"Request timestamp invalid" (401)**
   - Ensure system clocks are synchronized
   - Timestamp must be within 5 minutes of server time

3. **"Invalid request signature" (401)**
   - Verify `SERVICE_SECRET_KEY` is the same on both services
   - Check payload format: `{serviceId}:{timestamp}:{jsonBody}`
   - Ensure body is JSON-stringified consistently

4. **"Invalid client" (401)**
   - Check that `client_id` and `client_secret` are correct
   - For service-to-service, use the service name as client_id

### Debug Logging

Enable debug logging in services to see authentication details:

```bash
# In service .env
LOG_LEVEL=debug
DEBUG=auth:*
```

---

## Security Considerations

1. **Never commit API keys or secrets to git**
2. **Rotate API keys regularly**
3. **Use HTTPS in production**
4. **Monitor for replay attacks** (timestamp validation helps)
5. **Implement rate limiting** on authentication endpoints
6. **Log all authentication attempts** for audit purposes

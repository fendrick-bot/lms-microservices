#!/bin/bash
# OAuth/OIDC and Service-to-Service Authentication Test Script
# Run this script to test the authentication flows

set -e

# Configuration
USER_SERVICE_URL="${USER_SERVICE_URL:-http://localhost:3001}"
COURSE_SERVICE_URL="${COURSE_SERVICE_URL:-http://localhost:3002}"
API_GATEWAY_URL="${API_GATEWAY_URL:-http://localhost:3000}"
SERVICE_SECRET_KEY="${SERVICE_SECRET_KEY:-xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ}"

echo "=========================================="
echo "LMS Authentication Flow Test Script"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
GRAY='\033[0;37m'
NC='\033[0m' # No Color

# Helper function for API calls
api_request() {
    local method="$1"
    local url="$2"
    local headers="${3:-}"
    local body="${4:-}"
    
    local curl_opts="-s -w \"\\n%{http_code}\""
    
    if [ -n "$headers" ]; then
        curl_opts="$curl_opts -H \"$headers\""
    fi
    
    if [ "$method" != "GET" ] && [ -n "$body" ]; then
        curl_opts="$curl_opts -H \"Content-Type: application/json\" -d '$body'"
    fi
    
    response=$(eval "curl $curl_opts -X $method $url" 2>&1)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    echo "{\"http_code\": $http_code, \"body\": $body}"
}

# ==================== TEST 1: OIDC Discovery ====================
echo -e "${YELLOW}TEST 1: OIDC Discovery Endpoint${NC}"
echo "--------------------------------"

response=$(curl -s "$USER_SERVICE_URL/.well-known/openid-configuration")
if echo "$response" | grep -q "issuer"; then
    echo -e "${GREEN}✅ Discovery endpoint working${NC}"
    echo -e "${GRAY}   Issuer: $(echo "$response" | grep -o '"issuer":"[^"]*"' | cut -d'"' -f4)${NC}"
else
    echo -e "${RED}❌ Discovery endpoint failed${NC}"
fi
echo ""

# ==================== TEST 2: Client Credentials Flow ====================
echo -e "${YELLOW}TEST 2: Client Credentials Flow (Service-to-Service Auth)${NC}"
echo "----------------------------------------------------------"

response=$(curl -s -X POST "$USER_SERVICE_URL/oauth/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=course-service" \
    -d "client_secret=course-service_g7qMhbliy1fiMCStqr6HJ7OQ" \
    -d "scope=courses:read")

if echo "$response" | grep -q "access_token"; then
    echo -e "${GREEN}✅ Client Credentials flow working${NC}"
    access_token=$(echo "$response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    echo -e "${GRAY}   Access Token: ${access_token:0:30}...${NC}"
    echo -e "${GRAY}   Token Type: $(echo "$response" | grep -o '"token_type":"[^"]*"' | cut -d'"' -f4)${NC}"
else
    echo -e "${RED}❌ Client Credentials flow failed${NC}"
    echo "$response"
fi
echo ""

# ==================== TEST 3: Token Introspection ====================
echo -e "${YELLOW}TEST 3: Token Introspection${NC}"
echo "----------------------------"

if [ -n "$access_token" ]; then
    response=$(curl -s -X POST "$USER_SERVICE_URL/oauth/introspect" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$access_token\",\"token_type_hint\":\"access_token\"}")
    
    if echo "$response" | grep -q '"active":true'; then
        echo -e "${GREEN}✅ Token introspection working${NC}"
        echo -e "${GRAY}   Active: true${NC}"
    else
        echo -e "${RED}❌ Token introspection failed${NC}"
        echo "$response"
    fi
else
    echo -e "${YELLOW}⚠️ Skipping - no access token available${NC}"
fi
echo ""

# ==================== TEST 4: Service-to-Service HMAC Auth ====================
echo -e "${YELLOW}TEST 4: Service-to-Service HMAC Authentication${NC}"
echo "-----------------------------------------------"

# Generate HMAC signature
timestamp=$(date +%s000)
service_id="course-service"
api_key="course-service_g7qMhbliy1fiMCStqr6HJ7OQ"
body='{"token":"test-token"}'
payload="$service_id:$timestamp:$body"

# Generate HMAC-SHA256 signature (requires openssl)
signature=$(echo -n "$payload" | openssl dgst -sha256 -hmac "$SERVICE_SECRET_KEY" | sed 's/^.* //')

echo -e "${GRAY}   Headers:${NC}"
echo -e "${GRAY}     x-service-api-key: ${api_key:0:20}...${NC}"
echo -e "${GRAY}     x-service-id: $service_id${NC}"
echo -e "${GRAY}     x-timestamp: $timestamp${NC}"
echo -e "${GRAY}     x-signature: ${signature:0:30}...${NC}"

response=$(curl -s -X POST "$USER_SERVICE_URL/api/auth-verification/verify-token" \
    -H "Content-Type: application/json" \
    -H "x-service-api-key: $api_key" \
    -H "x-service-id: $service_id" \
    -H "x-timestamp: $timestamp" \
    -H "x-signature: $signature" \
    -d "$body")

# Expected to fail with invalid token, but auth should pass
if echo "$response" | grep -qi "invalid.*token"; then
    echo -e "${GREEN}✅ Service-to-Service HMAC authentication working (token validation failed as expected)${NC}"
elif echo "$response" | grep -q "success"; then
    echo -e "${GREEN}✅ Service-to-Service HMAC authentication working${NC}"
else
    echo -e "${RED}❌ Service-to-Service HMAC authentication failed${NC}"
    echo "$response"
fi
echo ""

# ==================== TEST 5: Token Revocation ====================
echo -e "${YELLOW}TEST 5: Token Revocation (RFC 7009)${NC}"
echo "------------------------------------"

if [ -n "$access_token" ]; then
    response=$(curl -s -X POST "$USER_SERVICE_URL/oauth/revoke" \
        -H "Content-Type: application/json" \
        -d "{\"token\":\"$access_token\",\"token_type_hint\":\"access_token\"}")
    
    # RFC 7009: Should return 200 even if token was invalid
    echo -e "${GREEN}✅ Token revocation endpoint responded${NC}"
else
    echo -e "${YELLOW}⚠️ Skipping - no access token available${NC}"
fi
echo ""

echo "=========================================="
echo "Test Script Complete"
echo "=========================================="

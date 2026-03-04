# OAuth/OIDC and Service-to-Service Authentication Test Script
# Run this script to test the authentication flows

param(
    [string]$UserServiceUrl = "http://localhost:3001",
    [string]$CourseServiceUrl = "http://localhost:3002",
    [string]$ApiGatewayUrl = "http://localhost:3000"
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "LMS Authentication Flow Test Script" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$script:BaseUrl = $UserServiceUrl
$script:AccessToken = $null
$script:RefreshToken = $null
$script:AuthCode = $null
$script:ClientId = "test-client-id"
$script:ClientSecret = "test-client-secret"
$script:CodeVerifier = $null

# Helper function for API calls
function Invoke-ApiRequest {
    param(
        [string]$Method = "GET",
        [string]$Uri,
        [hashtable]$Headers = @{},
        [object]$Body = $null,
        [switch]$SkipAuth
    )
    
    try {
        $params = @{
            Method = $Method
            Uri = $Uri
            Headers = $Headers
            ContentType = "application/json"
        }
        
        if ($Body -and $Method -ne "GET") {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-RestMethod @params
        return @{ Success = $true; Data = $response }
    }
    catch {
        $errorMsg = $_.Exception.Message
        # PowerShell 7 uses HttpResponseMessage; read error body via ErrorDetails
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            $errorMsg = "$errorMsg - $($_.ErrorDetails.Message)"
        } elseif ($_.Exception.Response) {
            try {
                $responseBody = $_.Exception.Response.Content.ReadAsStringAsync().Result
                $errorMsg = "$errorMsg - $responseBody"
            } catch {}
        }
        return @{ Success = $false; Error = $errorMsg }
    }
}

# ==================== TEST 1: OIDC Discovery ====================
Write-Host "TEST 1: OIDC Discovery Endpoint" -ForegroundColor Yellow
Write-Host "--------------------------------" -ForegroundColor Yellow

$result = Invoke-ApiRequest -Uri "$BaseUrl/.well-known/openid-configuration"
if ($result.Success) {
    Write-Host "✅ Discovery endpoint working" -ForegroundColor Green
    Write-Host "   Issuer: $($result.Data.issuer)" -ForegroundColor Gray
    Write-Host "   Authorization Endpoint: $($result.Data.authorization_endpoint)" -ForegroundColor Gray
    Write-Host "   Token Endpoint: $($result.Data.token_endpoint)" -ForegroundColor Gray
} else {
    Write-Host "❌ Discovery endpoint failed: $($result.Error)" -ForegroundColor Red
}
Write-Host ""

# ==================== TEST 2: Client Credentials Flow (Service-to-Service) ====================
Write-Host "TEST 2: Client Credentials Flow (Service-to-Service Auth)" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------" -ForegroundColor Yellow

$body = @{
    grant_type = "client_credentials"
    client_id = "course-service"
    client_secret = "course-service_g7qMhbliy1fiMCStqr6HJ7OQ"
    scope = "courses:read courses:write"
}

$result = Invoke-ApiRequest -Method POST -Uri "$BaseUrl/oauth/token" -Body $body
if ($result.Success) {
    Write-Host "✅ Client Credentials flow working" -ForegroundColor Green
    Write-Host "   Access Token: $($result.Data.access_token.Substring(0, 30))..." -ForegroundColor Gray
    Write-Host "   Token Type: $($result.Data.token_type)" -ForegroundColor Gray
    Write-Host "   Expires In: $($result.Data.expires_in) seconds" -ForegroundColor Gray
    $script:ServiceToken = $result.Data.access_token
} else {
    Write-Host "❌ Client Credentials flow failed: $($result.Error)" -ForegroundColor Red
}
Write-Host ""

# ==================== TEST 3: Token Introspection ====================
Write-Host "TEST 3: Token Introspection" -ForegroundColor Yellow
Write-Host "----------------------------" -ForegroundColor Yellow

if ($script:ServiceToken) {
    $body = @{
        token = $script:ServiceToken
        token_type_hint = "access_token"
    }
    
    $result = Invoke-ApiRequest -Method POST -Uri "$BaseUrl/oauth/introspect" -Body $body
    if ($result.Success) {
        Write-Host "✅ Token introspection working" -ForegroundColor Green
        Write-Host "   Active: $($result.Data.active)" -ForegroundColor Gray
        if ($result.Data.active) {
            Write-Host "   Client ID: $($result.Data.client_id)" -ForegroundColor Gray
            Write-Host "   Scope: $($result.Data.scope)" -ForegroundColor Gray
        }
    } else {
        Write-Host "❌ Token introspection failed: $($result.Error)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️ Skipping - no service token available" -ForegroundColor Yellow
}
Write-Host ""

# ==================== TEST 4: Service-to-Service HMAC Authentication ====================
Write-Host "TEST 4: Service-to-Service HMAC Authentication" -ForegroundColor Yellow
Write-Host "-----------------------------------------------" -ForegroundColor Yellow

function Test-ServiceToServiceAuth {
    param(
        [string]$TargetServiceUrl,
        [string]$ServiceId = "course-service",
        [string]$ApiKey = "course-service_g7qMhbliy1fiMCStqr6HJ7OQ",
        [string]$SecretKey = "xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ"
    )
    
    $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()
    $body = @{ test = "data"; timestamp = Get-Date -Format "o" }
    $payload = "$ServiceId`:$timestamp`:$($body | ConvertTo-Json -Compress)"
    
    # Generate HMAC signature
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $signature = [System.BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace "-", "".ToLower()
    
    $headers = @{
        "x-service-api-key" = $ApiKey
        "x-service-id" = $ServiceId
        "x-timestamp" = $timestamp
        "x-signature" = $signature.ToLower()
    }
    
    Write-Host "   Headers:" -ForegroundColor Gray
    Write-Host "     x-service-api-key: $($ApiKey.Substring(0, 20))..." -ForegroundColor Gray
    Write-Host "     x-service-id: $ServiceId" -ForegroundColor Gray
    Write-Host "     x-timestamp: $timestamp" -ForegroundColor Gray
    Write-Host "     x-signature: $($signature.Substring(0, 30))..." -ForegroundColor Gray
    
    return Invoke-ApiRequest -Method POST -Uri "$TargetServiceUrl/api/test/service-auth" -Headers $headers -Body $body
}

# Test against user service auth verification endpoint
$timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString()
$body = @{ token = "test-token" }
$payload = "course-service:$timestamp`:$($body | ConvertTo-Json -Compress)"

$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = [System.Text.Encoding]::UTF8.GetBytes("xKMWsXYjCQ2Ja8ak4O9CEsIJAv5L41fozDGnxKnFoJMiC4i2yEg3fv9UWDKORYuUqAs4lJCMKQYc862HVDFEQ")
$signature = [System.BitConverter]::ToString($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))) -replace "-", "".ToLower()

$headers = @{
    "x-service-api-key" = "course-service_g7qMhbliy1fiMCStqr6HJ7OQ"
    "x-service-id" = "course-service"
    "x-timestamp" = $timestamp
    "x-signature" = $signature.ToLower()
}

$result = Invoke-ApiRequest -Method POST -Uri "$BaseUrl/api/auth-verification/verify-token" -Headers $headers -Body $body
if ($result.Success) {
    Write-Host "✅ Service-to-Service HMAC authentication working" -ForegroundColor Green
} else {
    # Expected to fail with invalid token, but auth should pass
    if ($result.Error -like "*invalid*token*" -or $result.Error -like "*Invalid token*") {
        Write-Host "✅ Service-to-Service HMAC authentication working (token validation failed as expected)" -ForegroundColor Green
    } else {
        Write-Host "❌ Service-to-Service HMAC authentication failed: $($result.Error)" -ForegroundColor Red
    }
}
Write-Host ""

# ==================== TEST 5: Token Revocation ====================
Write-Host "TEST 5: Token Revocation (RFC 7009)" -ForegroundColor Yellow
Write-Host "------------------------------------" -ForegroundColor Yellow

if ($script:ServiceToken) {
    $body = @{
        token = $script:ServiceToken
        token_type_hint = "access_token"
    }
    
    $result = Invoke-ApiRequest -Method POST -Uri "$BaseUrl/oauth/revoke" -Body $body
    if ($result.Success) {
        Write-Host "✅ Token revocation working" -ForegroundColor Green
    } else {
        Write-Host "❌ Token revocation failed: $($result.Error)" -ForegroundColor Red
    }
} else {
    Write-Host "⚠️ Skipping - no service token available" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Test Script Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

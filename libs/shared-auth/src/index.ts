export { AuthClient, createAuthClient } from './auth-client';
export { 
  createAuthMiddleware, 
  createAuthorizationMiddleware, 
  createProtectedRoute,
  AuthenticatedRequest 
} from './middleware/auth.middleware';
export type {
  UserData,
  TokenVerificationResult,
  PermissionCheckResult,
  UserProfile
} from './auth-client';

// OAuth 2.0 / OIDC exports
export { OAuthClient } from './oauth/oauth-client';
export { TokenIntrospector } from './oauth/token-introspector';
export { createOAuthMiddleware, OAuthAuthenticatedRequest } from './oauth/oauth.middleware';
export { createZeroTrustMiddleware, ZeroTrustRequest } from './zero-trust/zero-trust.middleware';
export { RedisCache } from './cache/redis-cache';
export type {
  OAuthConfig,
  TokenResponse,
  IntrospectionResponse,
  TrustContext,
  RiskFactor,
  RiskFactorType,
} from './types';

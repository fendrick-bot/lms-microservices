/**
 * OAuth 2.0 / OIDC Types
 */

export interface OAuthConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  userInfoEndpoint: string;
  introspectionEndpoint: string;
  revocationEndpoint: string;
  jwksUri: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
}

/**
 * Zero-Trust Types
 */

export interface TrustContext {
  userId: string;
  sessionId: string;
  deviceFingerprint: string;
  ipAddress: string;
  userAgent: string;
  timestamp: number;
  trustScore: number;
  riskFactors: RiskFactor[];
  lastVerified: number;
}

export interface RiskFactor {
  type: RiskFactorType;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: number;
}

export enum RiskFactorType {
  NEW_DEVICE = 'new_device',
  NEW_LOCATION = 'new_location',
  SUSPICIOUS_IP = 'suspicious_ip',
  UNUSUAL_TIME = 'unusual_time',
  RAPID_REQUESTS = 'rapid_requests',
  TOKEN_ANOMALY = 'token_anomaly',
  PERMISSION_ESCALATION = 'permission_escalation',
  MFA_NOT_VERIFIED = 'mfa_not_verified',
}

/**
 * Cache Types
 */

export interface CacheConfig {
  host: string;
  port: number;
  password?: string;
  db?: number;
  keyPrefix?: string;
}

export interface CachedToken {
  userId: string;
  email: string;
  role: string;
  scope?: string;
  exp: number;
}

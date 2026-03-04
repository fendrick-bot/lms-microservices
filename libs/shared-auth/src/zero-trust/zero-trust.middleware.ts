import { Request, Response, NextFunction } from 'express';
import { logger } from '@lms/logger';
import { TokenIntrospector } from '../oauth/token-introspector';
import { RedisCache } from '../cache/redis-cache';
import { TrustContext, RiskFactor, RiskFactorType } from '../types';

export interface ZeroTrustRequest extends Request {
  user?: {
    id: string;
    email?: string;
    role?: string;
    scope?: string[];
    trustScore: number;
    sessionId: string;
  };
  trustContext?: TrustContext;
  deviceFingerprint?: string;
}

interface ZeroTrustConfig {
  minTrustScore: number;
  reauthThreshold: number;
  stepUpThreshold: number;
  sessionMaxAge: number;
  continuousValidationInterval: number;
  idleTimeout: number;
  riskWeights: Record<RiskFactorType, number>;
  enableDeviceFingerprinting: boolean;
  enableBehavioralAnalysis: boolean;
}

const defaultConfig: ZeroTrustConfig = {
  minTrustScore: 50,
  reauthThreshold: 30,
  stepUpThreshold: 60,
  sessionMaxAge: 8 * 60 * 60,
  continuousValidationInterval: 15 * 60,
  idleTimeout: 30 * 60,
  riskWeights: {
    [RiskFactorType.NEW_DEVICE]: 20,
    [RiskFactorType.NEW_LOCATION]: 15,
    [RiskFactorType.SUSPICIOUS_IP]: 30,
    [RiskFactorType.UNUSUAL_TIME]: 10,
    [RiskFactorType.RAPID_REQUESTS]: 15,
    [RiskFactorType.TOKEN_ANOMALY]: 40,
    [RiskFactorType.PERMISSION_ESCALATION]: 35,
    [RiskFactorType.MFA_NOT_VERIFIED]: 25,
  },
  enableDeviceFingerprinting: true,
  enableBehavioralAnalysis: true,
};

/**
 * Zero-Trust Middleware Factory
 * Implements: Never Trust, Always Verify | Least Privilege | Continuous Validation
 */
export function createZeroTrustMiddleware(
  introspector: TokenIntrospector,
  cache: RedisCache,
  config: Partial<ZeroTrustConfig> = {}
) {
  const mergedConfig = { ...defaultConfig, ...config };

  return async (req: ZeroTrustRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      // Step 1: Extract token
      const token = extractToken(req);
      if (!token) {
        res.status(401).json({
          error: 'authentication_required',
          error_description: 'Access token required',
        });
        return;
      }

      // Step 2: Verify token via introspection (verify every request)
      const introspection = await introspector.introspect(token, 'access_token');
      if (!introspection.active) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'Token is inactive or expired',
        });
        return;
      }

      // Step 3: Generate device fingerprint
      const deviceFingerprint = mergedConfig.enableDeviceFingerprinting
        ? generateDeviceFingerprint(req)
        : 'disabled';
      req.deviceFingerprint = deviceFingerprint;

      // Step 4: Build trust context
      const trustContext: TrustContext = {
        userId: introspection.sub || '',
        sessionId: `session:${introspection.sub}:${Date.now()}`,
        deviceFingerprint,
        ipAddress: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || 'unknown',
        timestamp: Date.now(),
        trustScore: 100,
        riskFactors: [],
        lastVerified: Date.now(),
      };

      // Step 5: Calculate trust score
      const trustScore = await calculateTrustScore(trustContext, cache, mergedConfig);
      trustContext.trustScore = trustScore;
      req.trustContext = trustContext;

      // Step 6: Evaluate trust score
      if (trustScore < mergedConfig.minTrustScore) {
        res.status(403).json({
          error: 'access_denied',
          error_description: 'Access denied due to security concerns',
          trust_score: trustScore,
          risk_factors: trustContext.riskFactors.map((rf) => ({
            type: rf.type,
            severity: rf.severity,
          })),
        });
        return;
      }

      if (trustScore < mergedConfig.reauthThreshold) {
        res.status(401).json({
          error: 'reauthentication_required',
          error_description: 'Re-authentication required',
          action: 'login',
        });
        return;
      }

      if (trustScore < mergedConfig.stepUpThreshold) {
        res.status(403).json({
          error: 'step_up_required',
          error_description: 'Additional verification required',
          action: 'mfa',
        });
        return;
      }

      // Step 7: Attach user to request
      req.user = {
        id: introspection.sub || '',
        email: introspection.username,
        scope: introspection.scope?.split(' ') || [],
        trustScore,
        sessionId: trustContext.sessionId,
      };

      // Step 8: Add security headers
      addSecurityHeaders(res, trustContext);

      next();
    } catch (error) {
      logger.error('Zero-Trust middleware error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Security verification failed',
      });
    }
  };
}

/**
 * Require specific scope(s) - Least Privilege Access
 */
export function requireScope(...requiredScopes: string[]) {
  return (req: ZeroTrustRequest, res: Response, next: NextFunction): void => {
    const userScopes = req.user?.scope || [];

    const hasScope = requiredScopes.some((scope) => userScopes.includes(scope));

    if (!hasScope) {
      // Log permission escalation attempt
      logger.warn('Insufficient scope', {
        userId: req.user?.id,
        required: requiredScopes,
        actual: userScopes,
      });

      res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required scope(s): ${requiredScopes.join(', ')}`,
      });
      return;
    }

    next();
  };
}

/**
 * Require specific role
 */
export function requireRole(...allowedRoles: string[]) {
  return (req: ZeroTrustRequest, res: Response, next: NextFunction): void => {
    const userRole = (req as any).user?.role;

    if (!userRole || !allowedRoles.includes(userRole)) {
      res.status(403).json({
        error: 'insufficient_permissions',
        error_description: 'Insufficient role permissions',
      });
      return;
    }

    next();
  };
}

// Helper functions

function extractToken(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7);
  }

  const cookie = req.headers.cookie;
  if (cookie) {
    const match = cookie.match(/access_token=([^;]+)/);
    if (match) return match[1];
  }

  return null;
}

function generateDeviceFingerprint(req: Request): string {
  const crypto = require('crypto');
  const components = [
    req.headers['user-agent'] || '',
    req.headers['accept-language'] || '',
    req.headers['accept-encoding'] || '',
    req.headers['dnt'] || '',
  ];

  if (!req.headers['x-forwarded-for']) {
    components.push(req.ip || '');
  }

  return crypto.createHash('sha256').update(components.join('|')).digest('hex').substring(0, 32);
}

async function calculateTrustScore(
  context: TrustContext,
  cache: RedisCache,
  config: ZeroTrustConfig
): Promise<number> {
  let score = 100;

  // Check for new device
  const lastContext = await cache.get(`user:context:${context.userId}`);
  if (lastContext) {
    const parsed = JSON.parse(lastContext);
    if (parsed.deviceFingerprint !== context.deviceFingerprint) {
      context.riskFactors.push({
        type: RiskFactorType.NEW_DEVICE,
        severity: 'medium',
        description: 'Login from new device',
        timestamp: Date.now(),
      });
      score -= config.riskWeights[RiskFactorType.NEW_DEVICE];
    }

    if (parsed.ipAddress !== context.ipAddress) {
      context.riskFactors.push({
        type: RiskFactorType.NEW_LOCATION,
        severity: 'low',
        description: 'Login from new IP address',
        timestamp: Date.now(),
      });
      score -= config.riskWeights[RiskFactorType.NEW_LOCATION];
    }
  }

  // Check request velocity
  const requestCount = await cache.getRateLimitCount(`requests:${context.userId}:1min`);
  if (requestCount > 100) {
    context.riskFactors.push({
      type: RiskFactorType.RAPID_REQUESTS,
      severity: 'medium',
      description: 'Unusually high request rate',
      timestamp: Date.now(),
    });
    score -= config.riskWeights[RiskFactorType.RAPID_REQUESTS];
  }

  // Check unusual time
  const hour = new Date().getHours();
  if (hour < 5 || hour > 23) {
    context.riskFactors.push({
      type: RiskFactorType.UNUSUAL_TIME,
      severity: 'low',
      description: 'Login at unusual hour',
      timestamp: Date.now(),
    });
    score -= config.riskWeights[RiskFactorType.UNUSUAL_TIME];
  }

  // Store context for next request
  await cache.set(
    `user:context:${context.userId}`,
    JSON.stringify({
      deviceFingerprint: context.deviceFingerprint,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: context.timestamp,
    }),
    86400 // 24 hours
  );

  return Math.max(0, score);
}

function addSecurityHeaders(res: Response, context: TrustContext): void {
  res.setHeader('X-Trust-Score', context.trustScore.toString());
  res.setHeader('X-Session-ID', context.sessionId);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
}

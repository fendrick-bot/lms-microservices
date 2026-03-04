import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { verifyAccessToken } from '../utils/jwt.utils';
import { RedisService } from '../services/redis.service';
import { AuditService, AuditEventType } from '../services/audit.service';
import { logger } from '@lms/logger';

/**
 * Zero-Trust Architecture Middleware
 * 
 * Core Principles:
 * 1. Never Trust, Always Verify - Every request is authenticated and authorized
 * 2. Least Privilege Access - Users get minimum necessary permissions
 * 3. Continuous Validation - Re-verify context throughout the session
 * 4. Assume Breach - Design for containment and detection
 */

// Extended request interface for Zero-Trust
export interface ZeroTrustRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: string;
    trustScore: number;
    sessionId: string;
  };
  deviceFingerprint?: string;
  trustContext?: TrustContext;
}

// Trust context for continuous validation
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

// Risk factors that affect trust score
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

// Zero-Trust Configuration
interface ZeroTrustConfig {
  // Trust score thresholds
  minTrustScore: number; // Minimum score to allow access (0-100)
  reauthThreshold: number; // Score below which requires re-authentication
  stepUpThreshold: number; // Score below which requires step-up auth

  // Timing
  sessionMaxAge: number; // Maximum session age in seconds
  continuousValidationInterval: number; // How often to re-verify in seconds
  idleTimeout: number; // Idle timeout in seconds

  // Risk weights
  riskWeights: Record<RiskFactorType, number>;

  // Features
  enableDeviceFingerprinting: boolean;
  enableLocationTracking: boolean;
  enableBehavioralAnalysis: boolean;
  enableMFA: boolean;
}

// Default configuration
const defaultConfig: ZeroTrustConfig = {
  minTrustScore: 50,
  reauthThreshold: 30,
  stepUpThreshold: 60,
  sessionMaxAge: 8 * 60 * 60, // 8 hours
  continuousValidationInterval: 15 * 60, // 15 minutes
  idleTimeout: 30 * 60, // 30 minutes
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
  enableLocationTracking: true,
  enableBehavioralAnalysis: true,
  enableMFA: true,
};

/**
 * Zero-Trust Middleware Factory
 */
export class ZeroTrustMiddleware {
  private redis: RedisService;
  private audit: AuditService;
  private config: ZeroTrustConfig;

  constructor(config: Partial<ZeroTrustConfig> = {}) {
    this.redis = RedisService.getInstance();
    this.audit = AuditService.getInstance();
    this.config = { ...defaultConfig, ...config };
  }

  /**
   * Main Zero-Trust verification middleware
   * Verifies every request with continuous validation
   */
  verify(): (req: ZeroTrustRequest, res: Response, next: NextFunction) => Promise<void> {
    return async (req: ZeroTrustRequest, res: Response, next: NextFunction): Promise<void> => {
      try {
        // Step 1: Extract and validate token
        const token = this.extractToken(req);
        if (!token) {
          await this.logAccessDenied(req, 'missing_token');
          res.status(401).json({
            success: false,
            error: 'Authentication required',
            code: 'MISSING_TOKEN',
          });
          return;
        }

        // Step 2: Verify token and check revocation
        const tokenPayload = await this.verifyToken(token);
        if (!tokenPayload) {
          await this.logAccessDenied(req, 'invalid_token');
          res.status(401).json({
            success: false,
            error: 'Invalid or expired token',
            code: 'INVALID_TOKEN',
          });
          return;
        }

        // Step 3: Check if token is revoked
        const isRevoked = await this.redis.isTokenRevoked(token);
        if (isRevoked) {
          await this.logAccessDenied(req, 'revoked_token', tokenPayload.userId);
          res.status(401).json({
            success: false,
            error: 'Token has been revoked',
            code: 'REVOKED_TOKEN',
          });
          return;
        }

        // Step 4: Generate device fingerprint
        const deviceFingerprint = this.generateDeviceFingerprint(req);
        req.deviceFingerprint = deviceFingerprint;

        // Step 5: Build trust context
        const trustContext = await this.buildTrustContext(tokenPayload, deviceFingerprint, req);
        req.trustContext = trustContext;

        // Step 6: Calculate trust score
        const trustScore = await this.calculateTrustScore(trustContext, tokenPayload.userId);
        trustContext.trustScore = trustScore;

        // Step 7: Evaluate trust score
        if (trustScore < this.config.minTrustScore) {
          await this.handleLowTrust(req, res, trustContext, trustScore);
          return;
        }

        if (trustScore < this.config.reauthThreshold) {
          await this.requireReauthentication(req, res, trustContext);
          return;
        }

        if (trustScore < this.config.stepUpThreshold) {
          await this.requireStepUpAuth(req, res, trustContext);
          return;
        }

        // Step 8: Check for continuous validation
        const needsRevalidation = await this.needsContinuousValidation(tokenPayload.userId, trustContext);
        if (needsRevalidation) {
          await this.performContinuousValidation(req, res, trustContext, next);
          return;
        }

        // Step 9: Attach user with trust info
        req.user = {
          id: tokenPayload.userId,
          email: tokenPayload.email,
          role: tokenPayload.role,
          trustScore,
          sessionId: trustContext.sessionId,
        };

        // Step 10: Update context and allow request
        await this.updateTrustContext(trustContext);
        await this.logAccessGranted(req, trustContext);

        // Add security headers
        this.addSecurityHeaders(res, trustContext);

        next();
      } catch (error) {
        logger.error('Zero-Trust verification error:', error);
        await this.logAccessDenied(req, 'verification_error');
        res.status(500).json({
          success: false,
          error: 'Security verification failed',
        });
        return;
      }
    };
  }

  /**
   * Least Privilege middleware
   * Enforces that user only has minimum necessary permissions
   */
  requirePermission(resource: string, action: string) {
    return async (req: ZeroTrustRequest, res: Response, next: NextFunction) => {
      try {
        if (!req.user) {
          return res.status(401).json({
            success: false,
            error: 'Authentication required',
          });
        }

        // Check cached permission first
        const cachedPermission = await this.redis.getCachedPermission(req.user.id, resource, action);
        if (cachedPermission !== null) {
          if (!cachedPermission) {
            await this.audit.logAuthorization({
              userId: req.user.id,
              resource,
              action,
              granted: false,
              ipAddress: req.ip || 'unknown',
              userAgent: req.headers['user-agent'] || '',
              reason: 'cached_denial',
            });
            return res.status(403).json({
              success: false,
              error: 'Insufficient permissions',
            });
          }
          return next();
        }

        // Evaluate permission
        const hasPermission = await this.evaluatePermission(req.user.role, resource, action);

        // Cache result
        await this.redis.cachePermission(req.user.id, resource, action, hasPermission, 60);

        if (!hasPermission) {
          await this.audit.logAuthorization({
            userId: req.user.id,
            resource,
            action,
            granted: false,
            ipAddress: req.ip || 'unknown',
            userAgent: req.headers['user-agent'] || '',
            reason: 'rbac_denial',
          });

          // Add risk factor for permission escalation attempt
          if (req.trustContext) {
            req.trustContext.riskFactors.push({
              type: RiskFactorType.PERMISSION_ESCALATION,
              severity: 'high',
              description: `Attempted ${action} on ${resource} without permission`,
              timestamp: Date.now(),
            });
            await this.updateTrustContext(req.trustContext);
          }

          return res.status(403).json({
            success: false,
            error: 'Insufficient permissions',
          });
        }

        await this.audit.logAuthorization({
          userId: req.user.id,
          resource,
          action,
          granted: true,
          ipAddress: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || '',
        });

        next();
      } catch (error) {
        logger.error('Permission check error:', error);
        return res.status(500).json({
          success: false,
          error: 'Permission check failed',
        });
      }
    };
  }

  /**
   * Session validation middleware
   * Ensures session is still valid
   */
  validateSession() {
    return async (req: ZeroTrustRequest, res: Response, next: NextFunction) => {
      if (!req.user?.sessionId) {
        return res.status(401).json({
          success: false,
          error: 'Invalid session',
        });
      }

      const session = await this.redis.getSession(req.user.sessionId);
      if (!session) {
        await this.audit.logZeroTrustEvent({
          userId: req.user.id,
          eventType: AuditEventType.SESSION_TERMINATED,
          reason: 'Session expired or invalidated',
          ipAddress: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || '',
        });

        return res.status(401).json({
          success: false,
          error: 'Session expired',
          code: 'SESSION_EXPIRED',
        });
      }

      // Check idle timeout
      const idleTime = Date.now() - session.lastActivity;
      if (idleTime > this.config.idleTimeout * 1000) {
        await this.redis.deleteSession(req.user.sessionId);

        await this.audit.logZeroTrustEvent({
          userId: req.user.id,
          eventType: AuditEventType.SESSION_TERMINATED,
          reason: 'Idle timeout',
          ipAddress: req.ip || 'unknown',
          userAgent: req.headers['user-agent'] || '',
        });

        return res.status(401).json({
          success: false,
          error: 'Session expired due to inactivity',
          code: 'IDLE_TIMEOUT',
        });
      }

      // Update last activity
      session.lastActivity = Date.now();
      await this.redis.setSession(req.user.sessionId, session, this.config.sessionMaxAge);

      next();
    };
  }

  // Private helper methods

  private extractToken(req: Request): string | null {
    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      return authHeader.substring(7);
    }

    // Also check cookie
    const cookie = req.headers.cookie;
    if (cookie) {
      const match = cookie.match(/access_token=([^;]+)/);
      if (match) return match[1];
    }

    return null;
  }

  private async verifyToken(token: string): Promise<any | null> {
    try {
      // Check cache first
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const cached = await this.redis.getCachedTokenVerification(tokenHash);
      if (cached) return cached;

      // Verify token
      const payload = verifyAccessToken(token);

      // Cache result for 5 minutes
      await this.redis.cacheTokenVerification(tokenHash, payload, 300);

      return payload;
    } catch {
      return null;
    }
  }

  private generateDeviceFingerprint(req: Request): string {
    const components = [
      req.headers['user-agent'] || '',
      req.headers['accept-language'] || '',
      req.headers['accept-encoding'] || '',
      req.headers['dnt'] || '',
    ];

    // Add IP if not behind proxy
    if (!req.headers['x-forwarded-for']) {
      components.push(req.ip || '');
    }

    const fingerprint = crypto.createHash('sha256').update(components.join('|')).digest('hex');
    return fingerprint.substring(0, 32);
  }

  private async buildTrustContext(payload: any, deviceFingerprint: string, req: Request): Promise<TrustContext> {
    const sessionId = `session:${payload.userId}:${Date.now()}`;

    return {
      userId: payload.userId,
      sessionId,
      deviceFingerprint,
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || 'unknown',
      timestamp: Date.now(),
      trustScore: 100, // Start at 100, deduct for risk factors
      riskFactors: [],
      lastVerified: Date.now(),
    };
  }

  private async calculateTrustScore(context: TrustContext, userId: string): Promise<number> {
    let score = 100;

    // Check for new device
    const lastContext = await this.redis.getUserContext(userId);
    if (lastContext) {
      if (lastContext.deviceFingerprint !== context.deviceFingerprint) {
        context.riskFactors.push({
          type: RiskFactorType.NEW_DEVICE,
          severity: 'medium',
          description: 'Login from new device',
          timestamp: Date.now(),
        });
        score -= this.config.riskWeights[RiskFactorType.NEW_DEVICE];
      }

      if (lastContext.ipAddress !== context.ipAddress) {
        context.riskFactors.push({
          type: RiskFactorType.NEW_LOCATION,
          severity: 'low',
          description: 'Login from new IP address',
          timestamp: Date.now(),
        });
        score -= this.config.riskWeights[RiskFactorType.NEW_LOCATION];
      }
    }

    // Check for suspicious IP patterns
    if (await this.isSuspiciousIP(context.ipAddress)) {
      context.riskFactors.push({
        type: RiskFactorType.SUSPICIOUS_IP,
        severity: 'high',
        description: 'IP address flagged as suspicious',
        timestamp: Date.now(),
      });
      score -= this.config.riskWeights[RiskFactorType.SUSPICIOUS_IP];
    }

    // Check request velocity
    const requestCount = await this.redis.getRateLimitCount(`requests:${userId}:1min`);
    if (requestCount > 100) {
      context.riskFactors.push({
        type: RiskFactorType.RAPID_REQUESTS,
        severity: 'medium',
        description: 'Unusually high request rate',
        timestamp: Date.now(),
      });
      score -= this.config.riskWeights[RiskFactorType.RAPID_REQUESTS];
    }

    // Check unusual time (e.g., 3 AM local time)
    const hour = new Date().getHours();
    if (hour < 5 || hour > 23) {
      context.riskFactors.push({
        type: RiskFactorType.UNUSUAL_TIME,
        severity: 'low',
        description: 'Login at unusual hour',
        timestamp: Date.now(),
      });
      score -= this.config.riskWeights[RiskFactorType.UNUSUAL_TIME];
    }

    return Math.max(0, score);
  }

  private async isSuspiciousIP(ip: string): Promise<boolean> {
    // Check against known bad IPs or Tor exit nodes
    const isBlocked = await this.redis.exists(`blocked:ip:${ip}`);
    return isBlocked;
  }

  private async needsContinuousValidation(userId: string, context: TrustContext): Promise<boolean> {
    const timeSinceLastValidation = Date.now() - context.lastVerified;
    return timeSinceLastValidation > this.config.continuousValidationInterval * 1000;
  }

  private async performContinuousValidation(
    req: ZeroTrustRequest,
    res: Response,
    context: TrustContext,
    next: NextFunction
  ): Promise<void> {
    // Re-verify context
    const currentFingerprint = this.generateDeviceFingerprint(req);

    if (currentFingerprint !== context.deviceFingerprint) {
      await this.audit.logZeroTrustEvent({
        userId: context.userId,
        eventType: AuditEventType.CONTEXT_ANOMALY,
        reason: 'Device fingerprint changed during session',
        context: {
          originalFingerprint: context.deviceFingerprint,
          currentFingerprint,
        },
        ipAddress: req.ip || 'unknown',
        userAgent: req.headers['user-agent'] || '',
      });

      // Force re-authentication
      await this.requireReauthentication(req, res, context);
      return;
    }

    // Update last verified time
    context.lastVerified = Date.now();
    await this.updateTrustContext(context);

    next();
  }

  private async handleLowTrust(req: ZeroTrustRequest, res: Response, context: TrustContext, score: number): Promise<void> {
    await this.audit.logZeroTrustEvent({
      userId: context.userId,
      eventType: AuditEventType.REAUTHENTICATION_REQUIRED,
      reason: `Trust score too low: ${score}`,
      context: { riskFactors: context.riskFactors },
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
    });

    res.status(403).json({
      success: false,
      error: 'Access denied due to security concerns',
      code: 'LOW_TRUST_SCORE',
      details: {
        trustScore: score,
        riskFactors: context.riskFactors.map((rf) => ({
          type: rf.type,
          severity: rf.severity,
        })),
      },
    });
  }

  private async requireReauthentication(req: ZeroTrustRequest, res: Response, context: TrustContext): Promise<void> {
    await this.redis.requireReauthentication(context.userId, 'low_trust_score');

    await this.audit.logZeroTrustEvent({
      userId: context.userId,
      eventType: AuditEventType.REAUTHENTICATION_REQUIRED,
      reason: 'Trust score below threshold',
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
    });

    res.status(401).json({
      success: false,
      error: 'Re-authentication required',
      code: 'REAUTH_REQUIRED',
      action: 'login',
    });
  }

  private async requireStepUpAuth(req: ZeroTrustRequest, res: Response, context: TrustContext): Promise<void> {
    await this.audit.logZeroTrustEvent({
      userId: context.userId,
      eventType: AuditEventType.REAUTHENTICATION_REQUIRED,
      reason: 'Step-up authentication required',
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
    });

    res.status(403).json({
      success: false,
      error: 'Additional verification required',
      code: 'STEP_UP_REQUIRED',
      action: 'mfa',
    });
  }

  private async updateTrustContext(context: TrustContext): Promise<void> {
    await this.redis.recordUserContext(context.userId, {
      deviceFingerprint: context.deviceFingerprint,
      ipAddress: context.ipAddress,
      userAgent: context.userAgent,
      timestamp: context.timestamp,
    });

    // Store session
    await this.redis.setSession(
      context.sessionId,
      {
        userId: context.userId,
        trustScore: context.trustScore,
        riskFactors: context.riskFactors,
        lastActivity: Date.now(),
      },
      this.config.sessionMaxAge
    );
  }

  private async evaluatePermission(role: string, resource: string, action: string): Promise<boolean> {
    // RBAC implementation
    const permissions: Record<string, Record<string, string[]>> = {
      super_admin: { '*': ['*'] },
      teacher: {
        courses: ['create', 'read', 'update', 'delete'],
        assessments: ['create', 'read', 'update', 'delete'],
        students: ['read'],
        analytics: ['read'],
        'live-sessions': ['create', 'read', 'update', 'delete'],
        files: ['create', 'read', 'update', 'delete'],
      },
      student: {
        courses: ['read'],
        assessments: ['read', 'submit'],
        profile: ['read', 'update'],
        'live-sessions': ['read', 'join'],
        files: ['read'],
        payments: ['create', 'read'],
      },
      guest: {
        courses: ['read'],
        public: ['read'],
      },
    };

    const rolePermissions = permissions[role];
    if (!rolePermissions) return false;

    if (rolePermissions['*']?.includes('*')) return true;

    const resourcePermissions = rolePermissions[resource];
    if (!resourcePermissions) return false;

    return resourcePermissions.includes(action) || resourcePermissions.includes('*');
  }

  private async logAccessGranted(req: ZeroTrustRequest, context: TrustContext): Promise<void> {
    await this.audit.log({
      eventType: 'ACCESS_GRANTED',
      userId: context.userId,
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
      success: true,
      details: {
        trustScore: context.trustScore,
        riskFactorCount: context.riskFactors.length,
        path: req.path,
      },
    });
  }

  private async logAccessDenied(req: Request, reason: string, userId?: string): Promise<void> {
    await this.audit.log({
      eventType: 'ACCESS_DENIED',
      userId,
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
      success: false,
      details: {
        reason,
        path: req.path,
      },
    });
  }

  private addSecurityHeaders(res: Response, context: TrustContext): void {
    res.setHeader('X-Trust-Score', context.trustScore.toString());
    res.setHeader('X-Session-ID', context.sessionId);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
  }
}

// Convenience exports
export const zeroTrust = new ZeroTrustMiddleware();
export const verifyZeroTrust = () => zeroTrust.verify();
export const requirePermission = (resource: string, action: string) =>
  zeroTrust.requirePermission(resource, action);
export const validateSession = () => zeroTrust.validateSession();

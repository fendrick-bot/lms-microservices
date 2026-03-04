import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import { RedisService } from '../services/redis.service';
import { AuditService } from '../services/audit.service';
import { logger } from '@lms/logger';

/**
 * Rate Limiting Middleware
 * Implements various rate limiting strategies for different endpoints
 * Essential for preventing brute force attacks and DoS
 */

// Redis-backed store for rate limiting
class RedisRateLimitStore {
  private redis: RedisService;
  private prefix: string;

  constructor(prefix: string = 'ratelimit') {
    this.redis = RedisService.getInstance();
    this.prefix = prefix;
  }

  async increment(key: string): Promise<{ totalHits: number; resetTime: Date }> {
    const fullKey = `${this.prefix}:${key}`;
    const count = await this.redis.incrementRateLimit(fullKey, 60); // 1 minute window
    const resetTime = new Date(Date.now() + 60 * 1000);
    return { totalHits: count, resetTime };
  }

  async decrement(key: string): Promise<void> {
    const fullKey = `${this.prefix}:${key}`;
    const current = await this.redis.getRateLimitCount(fullKey);
    if (current > 0) {
      // Note: Redis INCR/DECR would be better, but this is a simplified version
      // In production, use a proper Redis rate limit implementation
    }
  }

  async resetKey(key: string): Promise<void> {
    const fullKey = `${this.prefix}:${key}`;
    await this.redis.del(fullKey);
  }
}

/**
 * Login rate limiter - strict limits on authentication endpoints
 * Prevents brute force attacks
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  skipSuccessfulRequests: true, // Don't count successful logins
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req: Request) => {
    // Use IP + email combination if available
    const email = req.body?.email || '';
    return `${req.ip}:${email}`;
  },
  handler: (req: Request, res: Response) => {
    const audit = AuditService.getInstance();
    audit.log({
      eventType: 'RATE_LIMIT_EXCEEDED',
      ipAddress: req.ip || 'unknown',
      userAgent: req.headers['user-agent'] || '',
      success: false,
      details: {
        endpoint: req.path,
        email: req.body?.email,
      },
    });

    logger.warn(`Rate limit exceeded for login`, {
      ip: req.ip,
      email: req.body?.email,
    });

    res.status(429).json({
      success: false,
      error: 'Too many login attempts',
      message: 'Please try again after 15 minutes',
      retryAfter: 900, // seconds
    });
  },
  message: {
    success: false,
    error: 'Too many login attempts',
    message: 'Please try again after 15 minutes',
  },
});

/**
 * Token endpoint rate limiter
 * Prevents token harvesting
 */
export const tokenRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Limit by client_id if available, otherwise IP
    return req.body?.client_id || req.ip || 'unknown';
  },
  handler: (req: Request, res: Response) => {
    logger.warn(`Rate limit exceeded for token endpoint`, {
      ip: req.ip,
      clientId: req.body?.client_id,
    });

    res.status(429).json({
      error: 'too_many_requests',
      error_description: 'Rate limit exceeded. Please try again later.',
    });
  },
});

/**
 * API general rate limiter
 * Standard protection for all API endpoints
 */
export const apiRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 100 requests per minute per user/IP
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    // Use user ID if authenticated, otherwise IP
    return (req as any).user?.id || req.ip || 'unknown';
  },
  skip: (req: Request) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/ready';
  },
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many requests. Please slow down.',
      retryAfter: 60,
    });
  },
});

/**
 * Strict rate limiter for sensitive operations
 * Used for password reset, MFA verification, etc.
 */
export const strictRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many attempts. Please try again after 1 hour.',
      retryAfter: 3600,
    });
  },
});

/**
 * OAuth authorization endpoint rate limiter
 * Prevents authorization code harvesting
 */
export const oauthAuthorizeRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10, // 10 authorization requests per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    return `${req.ip}:${req.query?.client_id || ''}`;
  },
  handler: (req: Request, res: Response) => {
    const redirectUri = req.query?.redirect_uri as string;
    if (redirectUri) {
      const url = new URL(redirectUri);
      url.searchParams.set('error', 'access_denied');
      url.searchParams.set('error_description', 'Rate limit exceeded');
      return res.redirect(url.toString());
    }

    res.status(429).json({
      error: 'access_denied',
      error_description: 'Rate limit exceeded',
    });
  },
});

/**
 * User registration rate limiter
 * Prevents spam account creation
 */
export const registrationRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    logger.warn(`Registration rate limit exceeded`, { ip: req.ip });

    res.status(429).json({
      success: false,
      error: 'Rate limit exceeded',
      message: 'Too many registration attempts. Please try again later.',
    });
  },
});

/**
 * Service-to-service rate limiter
 * Prevents service abuse
 */
export const serviceRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 1000, // 1000 requests per minute per service
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req: Request) => {
    return (req as any).serviceId || req.ip || 'unknown';
  },
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      success: false,
      error: 'Service rate limit exceeded',
      message: 'Too many requests from this service.',
    });
  },
});

/**
 * Custom sliding window rate limiter using Redis
 * More accurate than fixed window
 */
export class SlidingWindowRateLimiter {
  private redis: RedisService;
  private windowMs: number;
  private maxRequests: number;

  constructor(windowMs: number, maxRequests: number) {
    this.redis = RedisService.getInstance();
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  async isAllowed(key: string): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const now = Date.now();
    const windowStart = now - this.windowMs;
    const redisKey = `sliding:${key}`;

    // Remove old entries outside the window
    // Note: In production, use Redis sorted sets for proper sliding window
    // This is a simplified implementation

    const count = await this.redis.getRateLimitCount(redisKey);
    const allowed = count < this.maxRequests;

    if (allowed) {
      await this.redis.incrementRateLimit(redisKey, Math.ceil(this.windowMs / 1000));
    }

    return {
      allowed,
      remaining: Math.max(0, this.maxRequests - count - (allowed ? 1 : 0)),
      resetTime: now + this.windowMs,
    };
  }

  middleware() {
    return async (req: Request, res: Response, next: Function) => {
      const key = (req as any).user?.id || req.ip || 'unknown';
      const result = await this.isAllowed(key);

      // Set rate limit headers
      res.setHeader('X-RateLimit-Limit', this.maxRequests);
      res.setHeader('X-RateLimit-Remaining', result.remaining);
      res.setHeader('X-RateLimit-Reset', Math.ceil(result.resetTime / 1000));

      if (!result.allowed) {
        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded',
          retryAfter: Math.ceil(this.windowMs / 1000),
        });
      }

      next();
    };
  }
}

/**
 * Burst rate limiter
 * Allows short bursts but limits sustained traffic
 */
export class BurstRateLimiter {
  private redis: RedisService;
  private burstLimit: number;
  private sustainedLimit: number;
  private windowMs: number;

  constructor(burstLimit: number, sustainedLimit: number, windowMs: number = 60000) {
    this.redis = RedisService.getInstance();
    this.burstLimit = burstLimit;
    this.sustainedLimit = sustainedLimit;
    this.windowMs = windowMs;
  }

  async isAllowed(key: string): Promise<{ allowed: boolean; reason?: string }> {
    const burstKey = `burst:${key}`;
    const sustainedKey = `sustained:${key}`;

    // Check burst limit (very short window)
    const burstCount = await this.redis.getRateLimitCount(burstKey);
    if (burstCount >= this.burstLimit) {
      return { allowed: false, reason: 'burst_limit_exceeded' };
    }

    // Check sustained limit
    const sustainedCount = await this.redis.getRateLimitCount(sustainedKey);
    if (sustainedCount >= this.sustainedLimit) {
      return { allowed: false, reason: 'sustained_limit_exceeded' };
    }

    // Increment both counters
    await this.redis.incrementRateLimit(burstKey, 1); // 1 second burst window
    await this.redis.incrementRateLimit(sustainedKey, Math.ceil(this.windowMs / 1000));

    return { allowed: true };
  }

  middleware() {
    return async (req: Request, res: Response, next: Function) => {
      const key = (req as any).user?.id || req.ip || 'unknown';
      const result = await this.isAllowed(key);

      if (!result.allowed) {
        logger.warn(`Burst rate limit exceeded: ${result.reason}`, {
          ip: req.ip,
          userId: (req as any).user?.id,
        });

        return res.status(429).json({
          success: false,
          error: 'Rate limit exceeded',
          message: result.reason === 'burst_limit_exceeded'
            ? 'Too many requests in short period. Please slow down.'
            : 'Daily request limit exceeded.',
        });
      }

      next();
    };
  }
}

/**
 * Create a custom rate limiter with specific configuration
 */
export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  keyPrefix?: string;
  skipSuccessfulRequests?: boolean;
  errorMessage?: string;
}) {
  return rateLimit({
    windowMs: options.windowMs,
    max: options.max,
    skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      const prefix = options.keyPrefix || 'custom';
      const identifier = (req as any).user?.id || req.ip || 'unknown';
      return `${prefix}:${identifier}`;
    },
    handler: (req: Request, res: Response) => {
      res.status(429).json({
        success: false,
        error: 'Rate limit exceeded',
        message: options.errorMessage || 'Too many requests. Please try again later.',
        retryAfter: Math.ceil(options.windowMs / 1000),
      });
    },
  });
}

import { logger } from '@lms/logger';
import { CacheConfig, CachedToken } from '../types';

// Type definitions for Redis
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  setex(key: string, seconds: number, value: string): Promise<void>;
  del(key: string): Promise<void>;
  exists(key: string): Promise<number>;
  incr(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<void>;
  multi(): RedisMulti;
  ping(): Promise<string>;
  quit(): Promise<void>;
  on(event: string, callback: (...args: any[]) => void): void;
}

interface RedisMulti {
  incr(key: string): RedisMulti;
  expire(key: string, seconds: number): RedisMulti;
  exec(): Promise<any[]>;
}

// Dynamic import for ioredis
let Redis: any;
try {
  Redis = require('ioredis');
} catch {
  logger.warn('ioredis not installed, Redis cache will not be available');
}

/**
 * Redis Cache for token verification and permission caching
 * Essential for performance in Zero-Trust Architecture
 */
export class RedisCache {
  private client: RedisClient;
  private config: CacheConfig;
  private isConnected: boolean = false;

  constructor(config: CacheConfig) {
    this.config = config;
    this.client = new Redis({
      host: config.host,
      port: config.port,
      password: config.password,
      db: config.db || 0,
      keyPrefix: config.keyPrefix || 'auth:',
      retryStrategy: (times: number) => Math.min(times * 50, 2000),
      maxRetriesPerRequest: 3,
    });

    this.setupEventHandlers();
  }

  private setupEventHandlers(): void {
    this.client.on('connect', () => {
      logger.info('Redis cache connected');
      this.isConnected = true;
    });

    this.client.on('error', (err: Error) => {
      logger.error('Redis cache error:', err);
      this.isConnected = false;
    });
  }

  async connect(): Promise<void> {
    // ioredis connects automatically on first command
    // This method is for compatibility with other Redis clients
    if (!this.isConnected) {
      await this.client.ping();
    }
  }

  /**
   * Cache token verification result
   */
  async cacheTokenVerification(tokenHash: string, userData: CachedToken, ttlSeconds: number = 300): Promise<void> {
    const key = `token:${tokenHash}`;
    await this.client.setex(key, ttlSeconds, JSON.stringify(userData));
  }

  /**
   * Get cached token verification
   */
  async getCachedTokenVerification(tokenHash: string): Promise<CachedToken | null> {
    const key = `token:${tokenHash}`;
    const cached = await this.client.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  /**
   * Revoke a token (add to blacklist)
   */
  async revokeToken(tokenHash: string, expirySeconds: number): Promise<void> {
    const key = `revoked:${tokenHash}`;
    await this.client.setex(key, expirySeconds, 'revoked');
  }

  /**
   * Check if token is revoked
   */
  async isTokenRevoked(tokenHash: string): Promise<boolean> {
    const key = `revoked:${tokenHash}`;
    const result = await this.client.exists(key);
    return result === 1;
  }

  /**
   * Cache permission check result
   */
  async cachePermission(userId: string, resource: string, action: string, allowed: boolean, ttlSeconds: number = 60): Promise<void> {
    const key = `perm:${userId}:${resource}:${action}`;
    await this.client.setex(key, ttlSeconds, allowed ? '1' : '0');
  }

  /**
   * Get cached permission
   */
  async getCachedPermission(userId: string, resource: string, action: string): Promise<boolean | null> {
    const key = `perm:${userId}:${resource}:${action}`;
    const result = await this.client.get(key);
    if (result === null) return null;
    return result === '1';
  }

  /**
   * Store session data
   */
  async setSession(sessionId: string, data: any, ttlSeconds: number): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.setex(key, ttlSeconds, JSON.stringify(data));
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<any | null> {
    const key = `session:${sessionId}`;
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.del(key);
  }

  /**
   * Rate limiting - increment counter
   */
  async incrementRateLimit(key: string, windowSeconds: number): Promise<number> {
    const fullKey = `ratelimit:${key}`;
    const multi = this.client.multi();
    multi.incr(fullKey);
    multi.expire(fullKey, windowSeconds);
    const results = await multi.exec();
    return (results?.[0]?.[1] as number) || 1;
  }

  /**
   * Get rate limit count
   */
  async getRateLimitCount(key: string): Promise<number> {
    const fullKey = `ratelimit:${key}`;
    const count = await this.client.get(fullKey);
    return count ? parseInt(count, 10) : 0;
  }

  /**
   * General get/set operations
   */
  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.setex(key, ttlSeconds, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  /**
   * Health check
   */
  async healthCheck(): Promise<{ healthy: boolean; latency: number }> {
    const start = Date.now();
    try {
      await this.client.ping();
      return { healthy: true, latency: Date.now() - start };
    } catch {
      return { healthy: false, latency: Date.now() - start };
    }
  }

  /**
   * Disconnect
   */
  async disconnect(): Promise<void> {
    await this.client.quit();
    this.isConnected = false;
  }
}

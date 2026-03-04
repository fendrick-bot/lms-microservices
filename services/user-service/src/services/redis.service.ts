import Redis from 'ioredis';
import { logger } from '@lms/logger';

/**
 * Redis Service for caching, session management, and token blacklisting
 * Essential for Zero-Trust Architecture and OAuth 2.0 token revocation
 */
export class RedisService {
  private static instance: RedisService;
  private client: Redis;
  private isConnected: boolean = false;

  private constructor() {
    const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

    this.client = new Redis(redisUrl, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
      lazyConnect: true,
    });

    this.setupEventHandlers();
  }

  public static getInstance(): RedisService {
    if (!RedisService.instance) {
      RedisService.instance = new RedisService();
    }
    return RedisService.instance;
  }

  private setupEventHandlers(): void {
    this.client.on('connect', () => {
      logger.info('Redis client connected');
      this.isConnected = true;
    });

    this.client.on('ready', () => {
      logger.info('Redis client ready');
      this.isConnected = true;
    });

    this.client.on('error', (err) => {
      logger.error('Redis client error:', err);
      this.isConnected = false;
    });

    this.client.on('close', () => {
      logger.warn('Redis client connection closed');
      this.isConnected = false;
    });

    this.client.on('reconnecting', () => {
      logger.info('Redis client reconnecting...');
    });
  }

  public async connect(): Promise<void> {
    if (!this.isConnected) {
      await this.client.connect();
    }
  }

  public async disconnect(): Promise<void> {
    await this.client.quit();
    this.isConnected = false;
  }

  public getClient(): Redis {
    return this.client;
  }

  public isReady(): boolean {
    return this.isConnected && this.client.status === 'ready';
  }

  // Token Blacklist Operations

  /**
   * Add a token to the revocation blacklist
   * @param token - The JWT token to revoke
   * @param expirySeconds - Time until token naturally expires
   */
  public async revokeToken(token: string, expirySeconds: number): Promise<void> {
    const key = `token:revoked:${token}`;
    await this.client.setex(key, expirySeconds, 'revoked');
    logger.info('Token revoked', { key: key.substring(0, 50) + '...' });
  }

  /**
   * Check if a token has been revoked
   * @param token - The JWT token to check
   */
  public async isTokenRevoked(token: string): Promise<boolean> {
    const key = `token:revoked:${token}`;
    const result = await this.client.exists(key);
    return result === 1;
  }

  // Token Verification Cache

  /**
   * Cache token verification result
   * @param tokenHash - Hash of the token
   * @param userData - User data from verification
   * @param ttlSeconds - Cache TTL
   */
  public async cacheTokenVerification(tokenHash: string, userData: any, ttlSeconds: number = 300): Promise<void> {
    const key = `auth:token:${tokenHash}`;
    await this.client.setex(key, ttlSeconds, JSON.stringify(userData));
  }

  /**
   * Get cached token verification result
   * @param tokenHash - Hash of the token
   */
  public async getCachedTokenVerification(tokenHash: string): Promise<any | null> {
    const key = `auth:token:${tokenHash}`;
    const cached = await this.client.get(key);
    return cached ? JSON.parse(cached) : null;
  }

  // Rate Limiting

  /**
   * Increment rate limit counter
   * @param key - Rate limit key (e.g., 'ratelimit:login:ip:192.168.1.1')
   * @param windowSeconds - Time window
   */
  public async incrementRateLimit(key: string, windowSeconds: number): Promise<number> {
    const multi = this.client.multi();
    multi.incr(key);
    multi.expire(key, windowSeconds);
    const results = await multi.exec();
    return results?.[0]?.[1] as number || 1;
  }

  /**
   * Get current rate limit count
   * @param key - Rate limit key
   */
  public async getRateLimitCount(key: string): Promise<number> {
    const count = await this.client.get(key);
    return count ? parseInt(count, 10) : 0;
  }

  // Session Management

  /**
   * Store session data
   * @param sessionId - Unique session ID
   * @param data - Session data
   * @param ttlSeconds - Session TTL
   */
  public async setSession(sessionId: string, data: any, ttlSeconds: number = 3600): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.setex(key, ttlSeconds, JSON.stringify(data));
  }

  /**
   * Get session data
   * @param sessionId - Session ID
   */
  public async getSession(sessionId: string): Promise<any | null> {
    const key = `session:${sessionId}`;
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Delete session
   * @param sessionId - Session ID
   */
  public async deleteSession(sessionId: string): Promise<void> {
    const key = `session:${sessionId}`;
    await this.client.del(key);
  }

  // Permission Cache

  /**
   * Cache permission check result
   * @param userId - User ID
   * @param resource - Resource name
   * @param action - Action name
   * @param result - Permission result
   * @param ttlSeconds - Cache TTL
   */
  public async cachePermission(
    userId: string,
    resource: string,
    action: string,
    result: boolean,
    ttlSeconds: number = 60
  ): Promise<void> {
    const key = `perm:${userId}:${resource}:${action}`;
    await this.client.setex(key, ttlSeconds, result ? '1' : '0');
  }

  /**
   * Get cached permission
   * @param userId - User ID
   * @param resource - Resource name
   * @param action - Action name
   */
  public async getCachedPermission(userId: string, resource: string, action: string): Promise<boolean | null> {
    const key = `perm:${userId}:${resource}:${action}`;
    const result = await this.client.get(key);
    if (result === null) return null;
    return result === '1';
  }

  // OAuth State Management

  /**
   * Store OAuth state parameter
   * @param state - State value
   * @param data - Associated data
   * @param ttlSeconds - TTL
   */
  public async setOAuthState(state: string, data: any, ttlSeconds: number = 600): Promise<void> {
    const key = `oauth:state:${state}`;
    await this.client.setex(key, ttlSeconds, JSON.stringify(data));
  }

  /**
   * Get and delete OAuth state
   * @param state - State value
   */
  public async getOAuthState(state: string): Promise<any | null> {
    const key = `oauth:state:${state}`;
    const data = await this.client.get(key);
    if (data) {
      await this.client.del(key);
      return JSON.parse(data);
    }
    return null;
  }

  // Audit Log Buffer

  /**
   * Add audit event to buffer
   * @param event - Audit event
   */
  public async addAuditEvent(event: any): Promise<void> {
    const key = `audit:buffer`;
    await this.client.lpush(key, JSON.stringify(event));
    await this.client.ltrim(key, 0, 9999); // Keep last 10000 events
  }

  /**
   * Get audit events from buffer
   * @param count - Number of events to retrieve
   */
  public async getAuditEvents(count: number = 100): Promise<any[]> {
    const key = `audit:buffer`;
    const events = await this.client.lrange(key, 0, count - 1);
    return events.map((e) => JSON.parse(e));
  }

  /**
   * Remove processed audit events
   * @param count - Number of events to remove
   */
  public async removeAuditEvents(count: number): Promise<void> {
    const key = `audit:buffer`;
    await this.client.ltrim(key, count, -1);
  }

  // Zero-Trust Continuous Validation

  /**
   * Record device/context for continuous validation
   * @param userId - User ID
   * @param context - Device/context fingerprint
   */
  public async recordUserContext(userId: string, context: any): Promise<void> {
    const key = `user:context:${userId}`;
    await this.client.setex(key, 86400, JSON.stringify(context)); // 24 hours
  }

  /**
   * Get user's last known context
   * @param userId - User ID
   */
  public async getUserContext(userId: string): Promise<any | null> {
    const key = `user:context:${userId}`;
    const data = await this.client.get(key);
    return data ? JSON.parse(data) : null;
  }

  /**
   * Mark user for re-authentication (Zero-Trust)
   * @param userId - User ID
   * @param reason - Reason for re-auth
   */
  public async requireReauthentication(userId: string, reason: string): Promise<void> {
    const key = `user:reauth:${userId}`;
    await this.client.setex(key, 3600, reason); // 1 hour window
  }

  /**
   * Check if user needs re-authentication
   * @param userId - User ID
   */
  public async needsReauthentication(userId: string): Promise<string | null> {
    const key = `user:reauth:${userId}`;
    return await this.client.get(key);
  }

  // General Cache Operations

  public async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.setex(key, ttlSeconds, value);
    } else {
      await this.client.set(key, value);
    }
  }

  public async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  public async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(key);
    return result === 1;
  }

  public async expire(key: string, seconds: number): Promise<void> {
    await this.client.expire(key, seconds);
  }

  public async ttl(key: string): Promise<number> {
    return await this.client.ttl(key);
  }

  // Health Check

  public async healthCheck(): Promise<{ healthy: boolean; latency: number }> {
    const start = Date.now();
    try {
      await this.client.ping();
      return { healthy: true, latency: Date.now() - start };
    } catch (error) {
      return { healthy: false, latency: Date.now() - start };
    }
  }
}

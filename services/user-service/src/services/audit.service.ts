import { logger } from '@lms/logger';
import { RedisService } from './redis.service';

/**
 * Audit Event Types
 */
export enum AuditEventType {
  // Authentication Events
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILURE = 'LOGIN_FAILURE',
  LOGOUT = 'LOGOUT',
  TOKEN_ISSUANCE = 'TOKEN_ISSUANCE',
  TOKEN_REFRESH = 'TOKEN_REFRESH',
  TOKEN_REVOCATION = 'TOKEN_REVOCATION',
  TOKEN_VALIDATION = 'TOKEN_VALIDATION',
  TOKEN_VALIDATION_FAILURE = 'TOKEN_VALIDATION_FAILURE',

  // OAuth Events
  OAUTH_AUTHORIZE = 'OAUTH_AUTHORIZE',
  OAUTH_TOKEN_EXCHANGE = 'OAUTH_TOKEN_EXCHANGE',
  CLIENT_CREDENTIALS = 'CLIENT_CREDENTIALS',

  // Authorization Events
  ACCESS_DENIED = 'ACCESS_DENIED',
  ACCESS_GRANTED = 'ACCESS_GRANTED',
  PERMISSION_CHECK = 'PERMISSION_CHECK',

  // Zero-Trust Events
  REAUTHENTICATION_REQUIRED = 'REAUTHENTICATION_REQUIRED',
  CONTEXT_ANOMALY = 'CONTEXT_ANOMALY',
  SESSION_TERMINATED = 'SESSION_TERMINATED',

  // Service Events
  SERVICE_CALL = 'SERVICE_CALL',
  SERVICE_CALL_FAILURE = 'SERVICE_CALL_FAILURE',

  // Admin Events
  USER_CREATED = 'USER_CREATED',
  USER_UPDATED = 'USER_UPDATED',
  USER_DELETED = 'USER_DELETED',
  ROLE_CHANGED = 'ROLE_CHANGED',
  PERMISSIONS_MODIFIED = 'PERMISSIONS_MODIFIED',
}

/**
 * Audit Event Structure
 */
export interface AuditEvent {
  id?: string;
  timestamp: Date;
  eventType: AuditEventType | string;
  userId?: string;
  clientId?: string;
  serviceId?: string;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  resource?: string;
  action?: string;
  scope?: string;
  details?: Record<string, any>;
  errorMessage?: string;
  requestId?: string;
  sessionId?: string;
}

/**
 * Audit Service for comprehensive logging of authentication and authorization events
 * Essential for security monitoring, compliance, and forensics
 */
export class AuditService {
  private static instance: AuditService;
  private redis: RedisService;
  private buffer: AuditEvent[] = [];
  private flushInterval: NodeJS.Timeout | null = null;
  private readonly BUFFER_SIZE = 100;
  private readonly FLUSH_INTERVAL_MS = 5000; // 5 seconds

  private constructor() {
    this.redis = RedisService.getInstance();
    this.startFlushInterval();
  }

  public static getInstance(): AuditService {
    if (!AuditService.instance) {
      AuditService.instance = new AuditService();
    }
    return AuditService.instance;
  }

  /**
   * Log an audit event
   */
  public async log(event: Partial<AuditEvent>): Promise<void> {
    const fullEvent: AuditEvent = {
      timestamp: new Date(),
      eventType: event.eventType || 'UNKNOWN',
      userId: event.userId,
      clientId: event.clientId,
      serviceId: event.serviceId,
      ipAddress: event.ipAddress || 'unknown',
      userAgent: event.userAgent || 'unknown',
      success: event.success ?? true,
      resource: event.resource,
      action: event.action,
      scope: event.scope,
      details: event.details,
      errorMessage: event.errorMessage,
      requestId: event.requestId || this.generateRequestId(),
      sessionId: event.sessionId,
    };

    // Add to buffer
    this.buffer.push(fullEvent);

    // Flush if buffer is full
    if (this.buffer.length >= this.BUFFER_SIZE) {
      await this.flush();
    }

    // Also log critical events immediately
    if (this.isCriticalEvent(fullEvent.eventType)) {
      await this.logCriticalEvent(fullEvent);
    }
  }

  /**
   * Log authentication attempt
   */
  public async logAuthAttempt(params: {
    userId?: string;
    email?: string;
    ipAddress: string;
    userAgent: string;
    success: boolean;
    failureReason?: string;
    method: 'password' | 'oauth' | 'mfa' | 'sso';
  }): Promise<void> {
    await this.log({
      eventType: params.success ? AuditEventType.LOGIN_SUCCESS : AuditEventType.LOGIN_FAILURE,
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      success: params.success,
      details: {
        email: params.email,
        method: params.method,
      },
      errorMessage: params.failureReason,
    });

    // Check for brute force
    if (!params.success) {
      await this.checkBruteForce(params.ipAddress, params.email);
    }
  }

  /**
   * Log authorization decision
   */
  public async logAuthorization(params: {
    userId: string;
    resource: string;
    action: string;
    granted: boolean;
    ipAddress: string;
    userAgent: string;
    reason?: string;
  }): Promise<void> {
    await this.log({
      eventType: params.granted ? AuditEventType.ACCESS_GRANTED : AuditEventType.ACCESS_DENIED,
      userId: params.userId,
      resource: params.resource,
      action: params.action,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      success: params.granted,
      details: {
        reason: params.reason,
      },
    });
  }

  /**
   * Log service-to-service call
   */
  public async logServiceCall(params: {
    sourceService: string;
    targetService: string;
    endpoint: string;
    success: boolean;
    duration: number;
    errorMessage?: string;
  }): Promise<void> {
    await this.log({
      eventType: params.success ? AuditEventType.SERVICE_CALL : AuditEventType.SERVICE_CALL_FAILURE,
      serviceId: params.sourceService,
      ipAddress: 'internal',
      userAgent: 'service-client',
      success: params.success,
      details: {
        targetService: params.targetService,
        endpoint: params.endpoint,
        duration: params.duration,
      },
      errorMessage: params.errorMessage,
    });
  }

  /**
   * Log Zero-Trust security event
   */
  public async logZeroTrustEvent(params: {
    userId: string;
    eventType: AuditEventType.REAUTHENTICATION_REQUIRED | AuditEventType.CONTEXT_ANOMALY | AuditEventType.SESSION_TERMINATED;
    reason: string;
    context?: Record<string, any>;
    ipAddress: string;
    userAgent: string;
  }): Promise<void> {
    await this.log({
      eventType: params.eventType,
      userId: params.userId,
      ipAddress: params.ipAddress,
      userAgent: params.userAgent,
      success: true,
      details: {
        reason: params.reason,
        context: params.context,
      },
    });

    // Alert on critical security events
    logger.warn(`Zero-Trust Security Event: ${params.eventType}`, {
      userId: params.userId,
      reason: params.reason,
    });
  }

  /**
   * Get recent audit events
   */
  public async getRecentEvents(limit: number = 100): Promise<AuditEvent[]> {
    // First check buffer
    const buffered = this.buffer.slice(-limit);

    // Then get from Redis
    const redisEvents = await this.redis.getAuditEvents(limit - buffered.length);

    return [...redisEvents, ...buffered].slice(-limit);
  }

  /**
   * Get events for a specific user
   */
  public async getUserEvents(userId: string, limit: number = 100): Promise<AuditEvent[]> {
    const allEvents = await this.getRecentEvents(limit * 2);
    return allEvents.filter((e) => e.userId === userId).slice(-limit);
  }

  /**
   * Get failed login attempts for IP
   */
  public async getFailedLogins(ipAddress: string, minutes: number = 60): Promise<number> {
    const allEvents = await this.getRecentEvents(1000);
    const cutoff = new Date(Date.now() - minutes * 60 * 1000);

    return allEvents.filter(
      (e) =>
        e.ipAddress === ipAddress &&
        e.eventType === AuditEventType.LOGIN_FAILURE &&
        e.timestamp > cutoff
    ).length;
  }

  /**
   * Flush buffer to persistent storage
   */
  public async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const eventsToFlush = [...this.buffer];
    this.buffer = [];

    try {
      // Send to Redis buffer
      for (const event of eventsToFlush) {
        await this.redis.addAuditEvent(event);
      }

      // TODO: Also send to persistent storage (Elasticsearch, CloudWatch, etc.)
      // await this.sendToPersistentStorage(eventsToFlush);

      logger.debug(`Flushed ${eventsToFlush.length} audit events`);
    } catch (error) {
      logger.error('Failed to flush audit events:', error);
      // Put events back in buffer
      this.buffer.unshift(...eventsToFlush);
    }
  }

  /**
   * Shutdown audit service
   */
  public async shutdown(): Promise<void> {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
    }
    await this.flush();
  }

  private startFlushInterval(): void {
    this.flushInterval = setInterval(() => {
      this.flush().catch((err) => logger.error('Audit flush error:', err));
    }, this.FLUSH_INTERVAL_MS);
  }

  private isCriticalEvent(eventType: string): boolean {
    const criticalEvents = [
      AuditEventType.LOGIN_FAILURE,
      AuditEventType.ACCESS_DENIED,
      AuditEventType.TOKEN_VALIDATION_FAILURE,
      AuditEventType.REAUTHENTICATION_REQUIRED,
      AuditEventType.CONTEXT_ANOMALY,
      AuditEventType.SESSION_TERMINATED,
      AuditEventType.SERVICE_CALL_FAILURE,
    ];
    return criticalEvents.includes(eventType as AuditEventType);
  }

  private async logCriticalEvent(event: AuditEvent): Promise<void> {
    logger.warn(`Critical Audit Event: ${event.eventType}`, {
      userId: event.userId,
      ipAddress: event.ipAddress,
      success: event.success,
      details: event.details,
    });

    // TODO: Send to alerting system (PagerDuty, Slack, etc.)
    // await this.sendAlert(event);
  }

  private async checkBruteForce(ipAddress: string, email?: string): Promise<void> {
    const failedAttempts = await this.getFailedLogins(ipAddress, 15); // Last 15 minutes

    if (failedAttempts >= 5) {
      logger.warn(`Potential brute force attack from ${ipAddress}`, {
        failedAttempts,
        email,
      });

      // TODO: Implement IP blocking or CAPTCHA challenge
      // await this.blockIP(ipAddress, 60); // Block for 60 minutes
    }

    if (email) {
      const emailAttempts = (await this.getRecentEvents(1000)).filter(
        (e) =>
          e.details?.email === email &&
          e.eventType === AuditEventType.LOGIN_FAILURE &&
          e.timestamp > new Date(Date.now() - 15 * 60 * 1000)
      ).length;

      if (emailAttempts >= 5) {
        logger.warn(`Account lockout recommended for ${email}`, {
          failedAttempts: emailAttempts,
        });
      }
    }
  }

  private generateRequestId(): string {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 15)}`;
  }
}

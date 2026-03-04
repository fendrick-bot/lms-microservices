import { Request, Response, NextFunction } from 'express';
import { logger } from '@lms/logger';
import { HttpStatus, sendError } from '@lms/common';
import crypto from 'crypto';

interface ServiceAuthRequest extends Request {
  serviceId?: string;
}

/**
 * Middleware to authenticate service-to-service requests
 * Uses API keys and HMAC signatures for secure inter-service communication
 */
export const serviceAuthMiddleware = (
  req: ServiceAuthRequest,
  res: Response,
  next: NextFunction
) => {
  try {
    const serviceApiKey = req.headers['x-service-api-key'] as string;
    const serviceId = req.headers['x-service-id'] as string;
    const timestamp = req.headers['x-timestamp'] as string;
    const signature = req.headers['x-signature'] as string;

    console.log(serviceApiKey);
    console.log(serviceId);
    console.log(timestamp);
    console.log(signature);

    // Check required headers
    if (!serviceApiKey || !serviceId || !timestamp || !signature) {
      logger.warn('Service auth failed: Missing required headers', {
        serviceId,
        headers: req.headers,
      });
      return sendError(res, 'Service authentication required', HttpStatus.UNAUTHORIZED);
    }

    // Validate timestamp (prevent replay attacks)
    const requestTime = parseInt(timestamp);
    const currentTime = Date.now();
    const timeDiff = Math.abs(currentTime - requestTime);
    const maxTimeDiff = 5 * 60 * 1000; // 5 minutes

    if (timeDiff > maxTimeDiff) {
      logger.warn('Service auth failed: Request timestamp too old', {
        serviceId,
        requestTime,
        currentTime,
        timeDiff,
      });
      return sendError(res, 'Request timestamp invalid', HttpStatus.UNAUTHORIZED);
    }

    // Validate service credentials
    const validServices = {
      'course-service': process.env.COURSE_SERVICE_API_KEY,
      'payment-service': process.env.PAYMENT_SERVICE_API_KEY,
      'assessment-service': process.env.ASSESSMENT_SERVICE_API_KEY,
      'analytics-service': process.env.ANALYTICS_SERVICE_API_KEY,
      'notification-service': process.env.NOTIFICATION_SERVICE_API_KEY,
      'live-session-service': process.env.LIVE_SESSION_SERVICE_API_KEY,
      'file-service': process.env.FILE_SERVICE_API_KEY,
      'api-gateway': process.env.API_GATEWAY_SERVICE_KEY,
    };

    const expectedApiKey = validServices[serviceId as keyof typeof validServices];

    if (!expectedApiKey || serviceApiKey !== expectedApiKey) {
      logger.warn('Service auth failed: Invalid service credentials', {
        serviceId,
        providedKey: serviceApiKey?.substring(0, 8) + '...',
      });
      return sendError(res, 'Invalid service credentials', HttpStatus.UNAUTHORIZED);
    }

    // Verify HMAC signature
    const secretKey = process.env.SERVICE_SECRET_KEY || 'default-secret-key';
    const payload = `${serviceId}:${timestamp}:${JSON.stringify(req.body)}`;
    const expectedSignature = crypto.createHmac('sha256', secretKey).update(payload).digest('hex');

    if (signature !== expectedSignature) {
      logger.warn('Service auth failed: Invalid signature', {
        serviceId,
        expectedSignature: expectedSignature.substring(0, 8) + '...',
        providedSignature: signature.substring(0, 8) + '...',
      });
      return sendError(res, 'Invalid request signature', HttpStatus.UNAUTHORIZED);
    }

    // Authentication successful
    req.serviceId = serviceId;
    logger.info('Service authenticated successfully', { serviceId });
    next();
  } catch (error) {
    logger.error('Service auth middleware error:', error);
    if (res.headersSent) {
      return;
    }
    return sendError(res, 'Service authentication failed', HttpStatus.INTERNAL_SERVER_ERROR);
  }
};

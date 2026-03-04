import { Request, Response, NextFunction } from 'express';
import { TokenIntrospector } from './token-introspector';
import { logger } from '@lms/logger';

export interface OAuthAuthenticatedRequest extends Request {
  user?: {
    id: string;
    username?: string;
    scope?: string[];
    clientId?: string;
  };
  token?: string;
}

/**
 * Create OAuth 2.0 authentication middleware
 * Uses token introspection for "verify every request" approach
 */
export function createOAuthMiddleware(introspector: TokenIntrospector) {
  return async (req: OAuthAuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'Access token required',
        });
        return;
      }

      const token = authHeader.substring(7);

      // Introspect token - verify every request
      const introspection = await introspector.introspect(token, 'access_token');

      if (!introspection.active) {
        res.status(401).json({
          error: 'invalid_token',
          error_description: 'Token is inactive or expired',
        });
        return;
      }

      // Attach user info to request
      req.user = {
        id: introspection.sub || '',
        username: introspection.username,
        scope: introspection.scope?.split(' ') || [],
        clientId: introspection.client_id,
      };
      req.token = token;

      logger.debug('OAuth token verified', {
        userId: req.user.id,
        clientId: req.user.clientId,
      });

      next();
    } catch (error) {
      logger.error('OAuth middleware error:', error);
      res.status(500).json({
        error: 'server_error',
        error_description: 'Authentication check failed',
      });
    }
  };
}

/**
 * Create scope-based authorization middleware
 */
export function requireScope(...requiredScopes: string[]) {
  return (req: OAuthAuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user?.scope) {
      res.status(403).json({
        error: 'insufficient_scope',
        error_description: 'Token does not have required scopes',
      });
      return;
    }

    const hasScope = requiredScopes.some((scope) => req.user!.scope!.includes(scope));

    if (!hasScope) {
      res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required scope(s): ${requiredScopes.join(', ')}`,
      });
      return;
    }

    next();
  };
}

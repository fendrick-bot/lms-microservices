import { Router, Request, Response, NextFunction } from 'express';
import { OAuthServer } from '../oauth/oauth-server';
import { loginRateLimiter, tokenRateLimiter, oauthAuthorizeRateLimiter } from '../middleware/rate-limit.middleware';
import { body, query, validationResult } from 'express-validator';

const router: Router = Router();    
const oauthServer = new OAuthServer();

// Validation middleware
const validateRequest = (req: Request, res: Response, next: NextFunction): void => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({
      success: false,
      errors: errors.array(),
    });
    return;
  }
  next();
};

/**
 * @route   GET /.well-known/openid-configuration
 * @desc    OIDC Discovery endpoint
 * @access  Public
 */
router.get('/.well-known/openid-configuration', oauthServer.discovery.bind(oauthServer));

/**
 * @route   GET /oauth/jwks
 * @desc    JSON Web Key Set endpoint
 * @access  Public
 */
router.get('/oauth/jwks', (req, res) => {
  const { getJWKS } = require('../utils/jwt.utils');
  res.json(getJWKS());
});

/**
 * @route   GET /oauth/authorize
 * @desc    OAuth 2.0 Authorization endpoint (OIDC compatible)
 * @access  Public (requires user authentication)
 */
router.get(
  '/oauth/authorize',
  oauthAuthorizeRateLimiter,
  [
    query('response_type').notEmpty().withMessage('response_type is required'),
    query('client_id').notEmpty().withMessage('client_id is required'),
    query('redirect_uri').isURL().withMessage('valid redirect_uri is required'),
    query('scope').optional().isString(),
    query('state').optional().isString(),
    query('code_challenge').optional().isString(),
    query('code_challenge_method').optional().isIn(['S256', 'plain']),
    query('nonce').optional().isString(),
    validateRequest,
  ],
  oauthServer.authorize.bind(oauthServer)
);

/**
 * @route   POST /oauth/token
 * @desc    OAuth 2.0 Token endpoint
 * @access  Public (client authentication required)
 */
router.post(
  '/oauth/token',
  tokenRateLimiter,
  [
    body('grant_type')
      .notEmpty()
      .isIn(['authorization_code', 'refresh_token', 'client_credentials'])
      .withMessage('Invalid grant_type'),
    body('code').optional().isString(),
    body('redirect_uri').optional().isURL(),
    body('client_id').notEmpty().withMessage('client_id is required'),
    body('client_secret').notEmpty().withMessage('client_secret is required'),
    body('refresh_token').optional().isString(),
    body('code_verifier').optional().isString(),
    body('scope').optional().isString(),
    validateRequest,
  ],
  oauthServer.token.bind(oauthServer)
);

/**
 * @route   GET /oauth/userinfo
 * @desc    OIDC UserInfo endpoint
 * @access  Private (valid access token required)
 */
router.get('/oauth/userinfo', oauthServer.userInfo.bind(oauthServer));

/**
 * @route   POST /oauth/userinfo
 * @desc    OIDC UserInfo endpoint (POST method)
 * @access  Private (valid access token required)
 */
router.post('/oauth/userinfo', oauthServer.userInfo.bind(oauthServer));

/**
 * @route   POST /oauth/revoke
 * @desc    OAuth 2.0 Token Revocation endpoint (RFC 7009)
 * @access  Public (client authentication recommended)
 */
router.post(
  '/oauth/revoke',
  [
    body('token').notEmpty().withMessage('token is required'),
    body('token_type_hint').optional().isIn(['access_token', 'refresh_token']),
    validateRequest,
  ],
  oauthServer.revoke.bind(oauthServer)
);

/**
 * @route   POST /oauth/introspect
 * @desc    OAuth 2.0 Token Introspection endpoint (RFC 7662)
 * @access  Private (confidential clients only)
 */
router.post(
  '/oauth/introspect',
  [
    body('token').notEmpty().withMessage('token is required'),
    body('token_type_hint').optional().isIn(['access_token', 'refresh_token']),
    validateRequest,
  ],
  oauthServer.introspect.bind(oauthServer)
);

export default router;

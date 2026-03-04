import { Request, Response } from 'express';
import crypto from 'crypto';
import { db, users, refreshTokens, oauthClients, authorizationCodes } from '@lms/database';
import { eq, and, gt } from 'drizzle-orm';
import { logger } from '@lms/logger';
import { generateTokens, verifyAccessToken, verifyRefreshToken } from '../utils/jwt.utils';
import { TokenPayload } from '../utils/jwt.utils';
import { v4 as uuidv4 } from 'uuid';
import { RedisService } from '../services/redis.service';
import { AuditService } from '../services/audit.service';
import { AuthenticatedRequest } from '../types/user.types';

// OAuth 2.0 Grant Types
export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  REFRESH_TOKEN = 'refresh_token',
  CLIENT_CREDENTIALS = 'client_credentials',
  PASSWORD = 'password',
}

// OAuth 2.0 Response Types
export enum ResponseType {
  CODE = 'code',
  TOKEN = 'token',
  ID_TOKEN = 'id_token',
}

// OAuth 2.0 Scopes
export enum OAuthScope {
  OPENID = 'openid',
  PROFILE = 'profile',
  EMAIL = 'email',
  COURSES_READ = 'courses:read',
  COURSES_WRITE = 'courses:write',
  ASSESSMENTS_READ = 'assessments:read',
  ASSESSMENTS_WRITE = 'assessments:write',
  PAYMENTS = 'payments',
  ADMIN = 'admin',
}

// PKCE Code Challenge Method
export enum CodeChallengeMethod {
  S256 = 'S256',
  PLAIN = 'plain',
}

// OAuth Token Response
export interface TokenResponse {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string; // OIDC
}

// OIDC ID Token Claims
export interface IDTokenClaims {
  iss: string; // Issuer
  sub: string; // Subject (user ID)
  aud: string; // Audience (client ID)
  exp: number; // Expiration
  iat: number; // Issued at
  auth_time?: number; // Authentication time
  nonce?: string; // Nonce from auth request
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  roles?: string[];
}

// OAuth Error Response
export interface OAuthError {
  error: string;
  error_description?: string;
  error_uri?: string;
}

export class OAuthServer {
  private redis: RedisService;
  private audit: AuditService;
  private issuer: string;

  constructor() {
    this.redis = RedisService.getInstance();
    this.audit = AuditService.getInstance();
    this.issuer = process.env.OAUTH_ISSUER || 'https://auth.lms.local';
  }

  /**
   * OAuth 2.0 Authorization Endpoint (OIDC Compatible)
   * Handles authorization code flow with PKCE
   */
  async authorize(req: Request, res: Response): Promise<void> {
    try {
      const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
        nonce,
      } = req.query;

      // Validate required parameters
      if (!response_type || !client_id || !redirect_uri) {
        return this.redirectWithError(
          res,
          redirect_uri as string,
          'invalid_request',
          'Missing required parameters',
          state as string
        );
      }

      // Validate client
      const client = await this.validateClient(client_id as string, redirect_uri as string);
      if (!client) {
        return this.redirectWithError(
          res,
          redirect_uri as string,
          'unauthorized_client',
          'Invalid client or redirect URI',
          state as string
        );
      }

      // Validate response type
      if (response_type !== ResponseType.CODE) {
        return this.redirectWithError(
          res,
          redirect_uri as string,
          'unsupported_response_type',
          'Only authorization_code flow is supported',
          state as string
        );
      }

      // Parse and validate scopes
      const requestedScopes = (scope as string)?.split(' ') || [OAuthScope.OPENID];
      const validScopes = this.validateScopes(requestedScopes, client.allowedScopes);

      // Check if user is authenticated

      const user = (req as AuthenticatedRequest & { user?: { id: string; userId: string; email: string; role: string } }).user;
      if (!user) {
        // Store authorization request and redirect to login
        const requestId = uuidv4();
        await this.redis.set(
          `oauth:request:${requestId}`,
          JSON.stringify({
            response_type,
            client_id,
            redirect_uri,
            scope: validScopes.join(' '),
            state,
            code_challenge,
            code_challenge_method,
            nonce,
          }),
          // 10 minutes
            600, 
        );

        return res.redirect(`/login?oauth_request=${requestId}`);
      }

      // Generate authorization code with PKCE
      const code = await this.generateAuthorizationCode({
        userId: user.id,
        clientId: client_id as string,
        redirectUri: redirect_uri as string,
        scope: validScopes.join(' '),
        codeChallenge: code_challenge as string,
        codeChallengeMethod: (code_challenge_method as CodeChallengeMethod) || CodeChallengeMethod.S256,
        nonce: nonce as string,
      });

      // Log authorization
      await this.audit.log({
        eventType: 'OAUTH_AUTHORIZE',
        userId: user.id,
        clientId: client_id as string,
        scope: validScopes.join(' '),
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        success: true,
      });

      // Redirect with authorization code
      const redirectUrl = new URL(redirect_uri as string);
      redirectUrl.searchParams.set('code', code);
      if (state) redirectUrl.searchParams.set('state', state as string);

      res.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error('OAuth authorization error:', error);
      res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
    }
  }

  /**
   * OAuth 2.0 Token Endpoint
   * Handles token exchange for various grant types
   */
  async token(req: Request, res: Response): Promise<Response | void> {
    try {
      const { grant_type, code, redirect_uri, client_id, client_secret, refresh_token, code_verifier, scope } = req.body;

      // Authenticate client
      const client = await this.authenticateClient(client_id, client_secret);
      if (!client) {
        return res.status(401).json({
          error: 'invalid_client',
          error_description: 'Client authentication failed',
        });
      }

      let tokenResponse: TokenResponse;

      switch (grant_type) {
        case GrantType.AUTHORIZATION_CODE:
          tokenResponse = await this.handleAuthorizationCodeGrant(
            code,
            redirect_uri,
            client,
            code_verifier,
            req
          );
          break;

        case GrantType.REFRESH_TOKEN:
          tokenResponse = await this.handleRefreshTokenGrant(refresh_token, client, scope, req);
          break;

        case GrantType.CLIENT_CREDENTIALS:
          tokenResponse = await this.handleClientCredentialsGrant(client, scope, req);
          break;

        default:
          return res.status(400).json({
            error: 'unsupported_grant_type',
            error_description: `Grant type '${grant_type}' is not supported`,
          });
      }

      res.json(tokenResponse);
    } catch (error) {
      logger.error('OAuth token error:', error);
      res.status(500).json({ error: 'server_error', error_description: 'Internal server error' });
    }
  }

  /**
   * OIDC UserInfo Endpoint
   * Returns claims about the authenticated user
   */
  async userInfo(req: Request, res: Response): Promise<Response | void> {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Access token required' });
      }

      const token = authHeader.substring(7);
      const payload = verifyAccessToken(token);

      // Check if token is revoked
      const isRevoked = await this.redis.exists(`token:revoked:${token}`);
      if (isRevoked) {
        return res.status(401).json({ error: 'invalid_token', error_description: 'Token has been revoked' });
      }

      // Get user from database
      const userResult = await db
        .select({
          id: users.id,
          email: users.email,
          role: users.role,
          emailVerified: users.emailVerified,
        })
        .from(users)
        .where(eq(users.id, payload.userId))
        .limit(1);

      if (userResult.length === 0) {
        return res.status(404).json({ error: 'invalid_token', error_description: 'User not found' });
      }

      const user = userResult[0];

      // Build UserInfo response
      const userInfo: Record<string, any> = {
        sub: user.id,
      };

      // Include claims based on scope
      const scopes = payload.scope?.split(' ') || [];

      if (scopes.includes(OAuthScope.EMAIL)) {
        userInfo.email = user.email;
        userInfo.email_verified = user.emailVerified;
      }

      if (scopes.includes(OAuthScope.PROFILE)) {
        // Fetch profile data
        const { userProfiles } = await import('@lms/database');
        const profileResult = await db
          .select({
            firstName: userProfiles.firstName,
            lastName: userProfiles.lastName,
            bio: userProfiles.bio,
          })
          .from(userProfiles)
          .where(eq(userProfiles.userId, user.id))
          .limit(1);

        if (profileResult.length > 0) {
          const profile = profileResult[0];
          userInfo.name = `${profile.firstName || ''} ${profile.lastName || ''}`.trim();
          userInfo.given_name = profile.firstName;
          userInfo.family_name = profile.lastName;
        }
      }

      res.json(userInfo);
    } catch (error) {
      logger.error('UserInfo error:', error);
      res.status(401).json({ error: 'invalid_token', error_description: 'Invalid access token' });
    }
  }

  /**
   * OAuth 2.0 Token Revocation Endpoint (RFC 7009)
   */
  async revoke(req: Request, res: Response): Promise<Response | void> {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Token is required' });
      }

      // Try to identify token type and revoke
      let tokenType = token_type_hint;

      if (!tokenType) {
        // Try to determine token type
        try {
          verifyAccessToken(token);
          tokenType = 'access_token';
        } catch {
          tokenType = 'refresh_token';
        }
      }

      if (tokenType === 'access_token') {
        // Get token expiry and add to blacklist
        try {
          const payload = verifyAccessToken(token);
          const expiry = payload.exp * 1000 - Date.now();
          if (expiry > 0) {
            await this.redis.set(`token:revoked:${token}`, 'revoked', Math.ceil(expiry / 1000));
          }
        } catch {
          // Invalid token, still return 200 per RFC 7009
        }
      } else if (tokenType === 'refresh_token') {
        // Delete refresh token from database
        await db.delete(refreshTokens).where(eq(refreshTokens.token, token));
      }

      // Log revocation
      await this.audit.log({
        eventType: 'TOKEN_REVOCATION',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] || '',
        success: true,
        details: { tokenType },
      });

      // RFC 7009: Return 200 even if token was invalid
      res.status(200).json({});
    } catch (error) {
      logger.error('Token revocation error:', error);
      res.status(500).json({ error: 'server_error' });
    }
  }

  /**
   * OAuth 2.0 Token Introspection Endpoint (RFC 7662)
   */
  async introspect(req: Request, res: Response): Promise<Response  |void > {
    try {
      const { token, token_type_hint } = req.body;

      if (!token) {
        return res.status(400).json({ error: 'invalid_request', error_description: 'Token is required' });
      }

      // Try access token first
      try {
        const payload = verifyAccessToken(token);

        // Check if revoked
        const isRevoked = await this.redis.exists(`token:revoked:${token}`);
        if (isRevoked) {
          return res.json({ active: false });
        }

        return res.json({
          active: true,
          scope: payload.scope,
          client_id: payload.clientId,
          username: payload.email,
          token_type: 'Bearer',
          exp: payload.exp,
          iat: payload.iat,
          sub: payload.userId,
          aud: payload.clientId,
          iss: this.issuer,
        });
      } catch {
        // Not a valid access token, try refresh token
      }

      // Check refresh token
      const refreshTokenResult = await db
        .select()
        .from(refreshTokens)
        .where(and(eq(refreshTokens.token, token), gt(refreshTokens.expiresAt, new Date().toISOString())))
        .limit(1);

      if (refreshTokenResult.length > 0) {
        const rt = refreshTokenResult[0];
        return res.json({
          active: true,
          scope: rt.scope,
          client_id: rt.clientId,
          token_type: 'Refresh',
          exp: Math.floor(new Date(rt.expiresAt).getTime() / 1000),
          sub: rt.userId,
        });
      }
      
      // Token not found or expired
      res.json({ active: false });
    } catch (error) {
      logger.error('Token introspection error:', error);
      res.status(500).json({ error: 'server_error' });
    }
  }

  /**
   * OIDC Discovery Endpoint
   */
  async discovery(req: Request, res: Response): Promise<void> {
    const baseUrl = this.issuer;

    res.json({
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/oauth/authorize`,
      token_endpoint: `${baseUrl}/oauth/token`,
      userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
      revocation_endpoint: `${baseUrl}/oauth/revoke`,
      introspection_endpoint: `${baseUrl}/oauth/introspect`,
      jwks_uri: `${baseUrl}/oauth/jwks`,
      scopes_supported: Object.values(OAuthScope),
      response_types_supported: ['code', 'token', 'id_token', 'code token', 'code id_token', 'token id_token', 'code token id_token'],
      grant_types_supported: Object.values(GrantType),
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256', 'HS256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name', 'given_name', 'family_name', 'picture', 'roles'],
      code_challenge_methods_supported: ['S256', 'plain'],
    });
  }

  // Private helper methods

  private async validateClient(clientId: string, redirectUri: string): Promise<any | null> {
    const clientResult = await db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, clientId))
      .limit(1);

    if (clientResult.length === 0) return null;

    const client = clientResult[0];

    // Validate redirect URI
    const allowedUris = client.redirectUris as string[];
    if (!allowedUris.includes(redirectUri)) return null;

    return client;
  }

  private async authenticateClient(clientId: string, clientSecret: string): Promise<any | null> {
    const clientResult = await db
      .select()
      .from(oauthClients)
      .where(and(eq(oauthClients.clientId, clientId), eq(oauthClients.clientSecret, clientSecret)))
      .limit(1);

    return clientResult.length > 0 ? clientResult[0] : null;
  }

  private validateScopes(requested: string[], allowed: string[]): string[] {
    const allowedSet = new Set(allowed);
    return requested.filter((scope) => allowedSet.has(scope));
  }

  private async generateAuthorizationCode(params: {
    userId: string;
    clientId: string;
    redirectUri: string;
    scope: string;
    codeChallenge: string;
    codeChallengeMethod: CodeChallengeMethod;
    nonce?: string;
  }): Promise<string> {
    const code = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await db.insert(authorizationCodes).values({
      code,
      userId: params.userId,
      clientId: params.clientId,
      redirectUri: params.redirectUri,
      scope: params.scope,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      nonce: params.nonce,
      expiresAt: expiresAt.toISOString(),
      used: false,
    });

    return code;
  }

  private async handleAuthorizationCodeGrant(
    code: string,
    redirectUri: string,
    client: any,
    codeVerifier: string,
    req: Request
  ): Promise<TokenResponse> {
    // Get and validate authorization code
    const codeResult = await db
      .select()
      .from(authorizationCodes)
      .where(and(eq(authorizationCodes.code, code), eq(authorizationCodes.used, false), gt(authorizationCodes.expiresAt, new Date().toISOString())))
      .limit(1);

    if (codeResult.length === 0) {
      throw new Error('invalid_grant');
    }

    const authCode = codeResult[0];

    // Validate redirect URI matches
    if (authCode.redirectUri !== redirectUri) {
      throw new Error('invalid_grant');
    }

    // Validate PKCE
    if (authCode.codeChallenge) {
      const challenge = codeVerifier;
      let expectedChallenge: string;

      if (authCode.codeChallengeMethod === CodeChallengeMethod.S256) {
        expectedChallenge = crypto.createHash('sha256').update(challenge).digest('base64url');
      } else {
        expectedChallenge = challenge;
      }

      if (expectedChallenge !== authCode.codeChallenge) {
        throw new Error('invalid_grant');
      }
    }

    // Mark code as used
    await db.update(authorizationCodes).set({ used: true }).where(eq(authorizationCodes.code, code));

    // Get user
    const userResult = await db
      .select({
        id: users.id,
        email: users.email,
        role: users.role,
      })
      .from(users)
      .where(eq(users.id, authCode.userId))
      .limit(1);

    if (userResult.length === 0) {
      throw new Error('invalid_grant');
    }

    const user = userResult[0];

    // Generate tokens
    const tokens = generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
    } as TokenPayload);

    // Generate refresh token with rotation
    const refreshTokenValue = crypto.randomBytes(32).toString('base64url');
    const refreshTokenExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

    await db.insert(refreshTokens).values({
      token: refreshTokenValue,
      userId: user.id,
      clientId: client.clientId,
      scope: authCode.scope || undefined,
      expiresAt: refreshTokenExpiry.toISOString(),
      rotatedFrom: null,
    });

    // Generate ID token if openid scope requested
    let idToken: string | undefined;
    const scopes = authCode.scope?.split(' ') || [];
    if (scopes.includes(OAuthScope.OPENID)) {
      idToken = await this.generateIDToken(user, client.clientId, authCode.nonce || undefined, scopes);
    }

    // Log token issuance
    await this.audit.log({
      eventType: 'TOKEN_ISSUANCE',
      userId: user.id,
      clientId: client.clientId,
      scope: authCode.scope || undefined,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      success: true,
      details: { grantType: GrantType.AUTHORIZATION_CODE },
    });

    return {
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: tokens.expiresIn,
      refresh_token: refreshTokenValue,
      scope: authCode.scope || undefined,
      id_token: idToken,
    };
  }

  private async handleRefreshTokenGrant(
    refreshTokenValue: string,
    client: any,
    requestedScope: string,
    req: Request
  ): Promise<TokenResponse> {
    // Get refresh token
    const tokenResult = await db
      .select()
      .from(refreshTokens)
      .where(and(eq(refreshTokens.token, refreshTokenValue), gt(refreshTokens.expiresAt, new Date().toISOString())))
      .limit(1);

    if (tokenResult.length === 0) {
      throw new Error('invalid_grant');
    }

    const oldRefreshToken = tokenResult[0];

    // Validate client
    if (oldRefreshToken.clientId !== client.clientId) {
      throw new Error('invalid_grant');
    }

    // Check for token reuse (indicates theft)
    if (oldRefreshToken.reused) {
      // Revoke all tokens for this user/client pair
      await this.revokeAllUserTokens(oldRefreshToken.userId, client.clientId);
      throw new Error('invalid_grant');
    }

    // Determine scope (cannot expand scope)
    const scope = requestedScope
      ? this.validateScopes(requestedScope.split(' '), (oldRefreshToken.scope || '').split(' ')).join(' ')
      : oldRefreshToken.scope;

    // Get user
    const userResult = await db
      .select({
        id: users.id,
        email: users.email,
        role: users.role,
      })
      .from(users)
      .where(eq(users.id, oldRefreshToken.userId))
      .limit(1);

    if (userResult.length === 0) {
      throw new Error('invalid_grant');
    }

    const user = userResult[0];

    // Generate new tokens
    const tokens = generateTokens({
      userId: user.id,
      email: user.email,
      role: user.role,
    } as TokenPayload);

    // Rotate refresh token
    const newRefreshTokenValue = crypto.randomBytes(32).toString('base64url');
    const refreshTokenExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);

    await db.insert(refreshTokens).values({
      token: newRefreshTokenValue,
      userId: user.id,
      clientId: client.clientId,
      scope: scope || undefined,
      expiresAt: refreshTokenExpiry.toISOString(),
      rotatedFrom: oldRefreshToken.token,
    });

    // Mark old token as used
    await db.update(refreshTokens).set({ reused: true }).where(eq(refreshTokens.token, refreshTokenValue));

    // Log token refresh
    await this.audit.log({
      eventType: 'TOKEN_REFRESH',
      userId: user.id,
      clientId: client.clientId,
      scope: scope || undefined,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      success: true,
    });

    return {
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: tokens.expiresIn,
      refresh_token: newRefreshTokenValue,
      scope: scope || undefined,
    };
  }

  private async handleClientCredentialsGrant(client: any, requestedScope: string, req: Request): Promise<TokenResponse> {
    // Client credentials tokens are for service-to-service
    // allowedScopes is string[] (JSONB array), requestedScope is a space-separated string
    const allowedScopesArray: string[] = Array.isArray(client.allowedScopes)
      ? client.allowedScopes
      : (client.allowedScopes || '').split(' ');
    const scope = requestedScope
      ? this.validateScopes(requestedScope.split(' '), allowedScopesArray).join(' ')
      : '';

    const tokens = generateTokens({
      userId: `client:${client.clientId}`,
      email: '',
      role: 'service',
    } as TokenPayload);

    // Log
    await this.audit.log({
      eventType: 'CLIENT_CREDENTIALS',
      clientId: client.clientId,
      scope: scope || undefined,
      ipAddress: req.ip,
      userAgent: req.headers['user-agent'] || '',
      success: true,
    });

    return {
      access_token: tokens.accessToken,
      token_type: 'Bearer',
      expires_in: tokens.expiresIn,
      scope: scope || undefined,
    };
  }

  private async generateIDToken(user: any, clientId: string, nonce: string | undefined, scopes: string[]): Promise<string> {
    const { userProfiles } = await import('@lms/database');

    const now = Math.floor(Date.now() / 1000);
    const claims: IDTokenClaims = {
      iss: this.issuer,
      sub: user.id,
      aud: clientId,
      exp: now + 3600, // 1 hour
      iat: now,
      auth_time: now,
    };

    if (nonce) claims.nonce = nonce;

    if (scopes.includes(OAuthScope.EMAIL)) {
      claims.email = user.email;
    }

    if (scopes.includes(OAuthScope.PROFILE)) {
      const profileResult = await db
        .select({
          firstName: userProfiles.firstName,
          lastName: userProfiles.lastName,
        })
        .from(userProfiles)
        .where(eq(userProfiles.userId, user.id))
        .limit(1);

      if (profileResult.length > 0) {
        const profile = profileResult[0];
        claims.given_name = profile.firstName || undefined;
        claims.family_name = profile.lastName || undefined;
        claims.name = `${profile.firstName || ''} ${profile.lastName || ''}`.trim();
      }
    }

    // Sign with RS256 for OIDC compliance
    const { generateIDToken } = await import('../utils/jwt.utils');
    return generateIDToken(claims);
  }

  private async revokeAllUserTokens(userId: string, clientId: string): Promise<void> {
    await db.delete(refreshTokens).where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.clientId, clientId)));

    // Also blacklist any active access tokens
    // This requires tracking issued tokens, which we should implement
    logger.warn(`Revoked all tokens for user ${userId} due to suspected token theft`);
  }

  private redirectWithError(
    res: Response,
    redirectUri: string,
    error: string,
    description: string,
    state?: string
  ): void {
    const url = new URL(redirectUri);
    url.searchParams.set('error', error);
    url.searchParams.set('error_description', description);
    if (state) url.searchParams.set('state', state);
    res.redirect(url.toString());
  }
}

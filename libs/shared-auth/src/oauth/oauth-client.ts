import axios, { AxiosInstance } from 'axios';
import { logger } from '@lms/logger';
import { OAuthConfig, TokenResponse } from '../types';

/**
 * OAuth 2.0 Client for service-to-service and user authentication
 * Implements Authorization Code flow, Client Credentials, and Token Refresh
 */
export class OAuthClient {
  private axiosInstance: AxiosInstance;
  private config: OAuthConfig;
  private tokenCache: Map<string, { token: TokenResponse; expiresAt: number }> = new Map();

  constructor(config: OAuthConfig) {
    this.config = config;
    this.axiosInstance = axios.create({
      timeout: 10000,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
  }

  /**
   * Build authorization URL for Authorization Code flow
   */
  buildAuthorizationUrl(state?: string, codeChallenge?: string, nonce?: string): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: this.config.scope,
    });

    if (state) params.set('state', state);
    if (codeChallenge) {
      params.set('code_challenge', codeChallenge);
      params.set('code_challenge_method', 'S256');
    }
    if (nonce) params.set('nonce', nonce);

    return `${this.config.authorizationEndpoint}?${params.toString()}`;
  }

  /**
   * Exchange authorization code for tokens
   */
  async exchangeCode(code: string, codeVerifier?: string): Promise<TokenResponse> {
    try {
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.config.redirectUri,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });

      if (codeVerifier) {
        params.set('code_verifier', codeVerifier);
      }

      const response = await this.axiosInstance.post(this.config.tokenEndpoint, params.toString());
      const tokenResponse: TokenResponse = response.data;

      // Cache the token
      this.cacheToken(this.config.clientId, tokenResponse);

      return tokenResponse;
    } catch (error) {
      logger.error('OAuth code exchange failed:', error);
      throw new Error('Failed to exchange authorization code');
    }
  }

  /**
   * Client Credentials flow for service-to-service authentication
   */
  async getClientCredentialsToken(scope?: string): Promise<TokenResponse> {
    const cacheKey = `client_credentials:${scope || 'default'}`;

    // Check cache first
    const cached = this.tokenCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now() + 60000) {
      return cached.token;
    }

    try {
      const params = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });

      if (scope) {
        params.set('scope', scope);
      }

      const response = await this.axiosInstance.post(this.config.tokenEndpoint, params.toString());
      const tokenResponse: TokenResponse = response.data;

      // Cache the token
      this.cacheToken(cacheKey, tokenResponse);

      return tokenResponse;
    } catch (error) {
      logger.error('Client credentials token request failed:', error);
      throw new Error('Failed to obtain client credentials token');
    }
  }

  /**
   * Refresh an access token
   */
  async refreshToken(refreshToken: string, scope?: string): Promise<TokenResponse> {
    try {
      const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });

      if (scope) {
        params.set('scope', scope);
      }

      const response = await this.axiosInstance.post(this.config.tokenEndpoint, params.toString());
      const tokenResponse: TokenResponse = response.data;

      // Update cache
      this.cacheToken(this.config.clientId, tokenResponse);

      return tokenResponse;
    } catch (error) {
      logger.error('Token refresh failed:', error);
      throw new Error('Failed to refresh token');
    }
  }

  /**
   * Revoke a token
   */
  async revokeToken(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<void> {
    try {
      const params = new URLSearchParams({
        token,
        client_id: this.config.clientId,
        client_secret: this.config.clientSecret,
      });

      if (tokenTypeHint) {
        params.set('token_type_hint', tokenTypeHint);
      }

      await this.axiosInstance.post(this.config.revocationEndpoint, params.toString());

      // Remove from cache
      this.tokenCache.delete(this.config.clientId);
    } catch (error) {
      logger.error('Token revocation failed:', error);
      throw new Error('Failed to revoke token');
    }
  }

  /**
   * Get user info from UserInfo endpoint
   */
  async getUserInfo(accessToken: string): Promise<any> {
    try {
      const response = await axios.get(this.config.userInfoEndpoint, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      return response.data;
    } catch (error) {
      logger.error('UserInfo request failed:', error);
      throw new Error('Failed to get user info');
    }
  }

  /**
   * Generate PKCE code verifier and challenge
   */
  static generatePKCE(): { codeVerifier: string; codeChallenge: string } {
    const crypto = require('crypto');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

    return { codeVerifier, codeChallenge };
  }

  /**
   * Generate random state parameter
   */
  static generateState(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Generate nonce for OIDC
   */
  static generateNonce(): string {
    const crypto = require('crypto');
    return crypto.randomBytes(16).toString('hex');
  }

  private cacheToken(key: string, token: TokenResponse): void {
    const expiresAt = Date.now() + token.expires_in * 1000;
    this.tokenCache.set(key, { token, expiresAt });
  }
}

import axios from 'axios';
import { logger } from '@lms/logger';
import { IntrospectionResponse } from '../types';

/**
 * OAuth 2.0 Token Introspector
 * Validates tokens using the introspection endpoint (RFC 7662)
 * Essential for Zero-Trust Architecture - verify every request
 */
export class TokenIntrospector {
  private introspectionEndpoint: string;
  private clientId: string;
  private clientSecret: string;
  private cache: Map<string, { response: IntrospectionResponse; expiresAt: number }> = new Map();

  constructor(config: {
    introspectionEndpoint: string;
    clientId: string;
    clientSecret: string;
  }) {
    this.introspectionEndpoint = config.introspectionEndpoint;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
  }

  /**
   * Introspect a token to check if it's active and get its metadata
   * This is the core of "verify every request" in Zero-Trust
   */
  async introspect(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<IntrospectionResponse> {
    // Check cache first (short cache for performance)
    const cacheKey = `${token}:${tokenTypeHint || ''}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.response;
    }

    try {
      const params = new URLSearchParams({
        token,
        client_id: this.clientId,
        client_secret: this.clientSecret,
      });

      if (tokenTypeHint) {
        params.set('token_type_hint', tokenTypeHint);
      }

      const response = await axios.post(this.introspectionEndpoint, params.toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        timeout: 5000,
      });

      const introspectionResponse: IntrospectionResponse = response.data;

      // Cache active tokens for 30 seconds to reduce introspection load
      if (introspectionResponse.active) {
        this.cache.set(cacheKey, {
          response: introspectionResponse,
          expiresAt: Date.now() + 30000, // 30 seconds
        });
      }

      return introspectionResponse;
    } catch (error) {
      logger.error('Token introspection failed:', error);
      // Return inactive on error (fail secure)
      return { active: false };
    }
  }

  /**
   * Quick check if token is active
   */
  async isActive(token: string, tokenTypeHint?: 'access_token' | 'refresh_token'): Promise<boolean> {
    const result = await this.introspect(token, tokenTypeHint);
    return result.active;
  }

  /**
   * Get token scopes
   */
  async getScopes(token: string): Promise<string[]> {
    const result = await this.introspect(token, 'access_token');
    if (!result.active || !result.scope) {
      return [];
    }
    return result.scope.split(' ');
  }

  /**
   * Check if token has specific scope
   */
  async hasScope(token: string, scope: string): Promise<boolean> {
    const scopes = await this.getScopes(token);
    return scopes.includes(scope);
  }

  /**
   * Clear the introspection cache
   */
  clearCache(): void {
    this.cache.clear();
  }

  /**
   * Get cache stats for monitoring
   */
  getCacheStats(): { size: number; hitRate: number } {
    return {
      size: this.cache.size,
      hitRate: 0, // Would need to track hits/misses for real metric
    };
  }
}

import jwt from 'jsonwebtoken';
import { config } from '../config/config';
import { logger } from '@lms/logger';
import { StringValue } from 'ms';
import crypto from 'crypto';

export interface TokenPayloadAuth {

  userId: string;
  email: string;
  role: string;
  scope?: string;
  clientId?: string;
}
export interface TokenPayload {
  iat: number,
  exp:number,
  userId: string;
  email: string;
  role: string;
  scope?: string;
  clientId?: string;
}

export interface JWTTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// OIDC ID Token Claims
export interface IDTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  auth_time?: number;
  nonce?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  roles?: string[];
}

// In-memory key pair for signing (in production, use proper key management)
let privateKey: string;
let publicKey: string;

/**
 * Generate RSA key pair for OIDC signing
 * In production, load from secure key management (AWS KMS, HashiCorp Vault, etc.)
 */
export const initializeKeys = (): void => {
  try {
    // Check if keys are provided via environment
    if (process.env.OIDC_PRIVATE_KEY && process.env.OIDC_PUBLIC_KEY) {
      privateKey = Buffer.from(process.env.OIDC_PRIVATE_KEY, 'base64').toString();
      publicKey = Buffer.from(process.env.OIDC_PUBLIC_KEY, 'base64').toString();
    } else {
      // Generate new key pair for development
      logger.warn('Generating development RSA keys. Use proper key management in production!');
      const { generateKeyPairSync } = require('crypto');
      const keys = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });
      privateKey = keys.privateKey;
      publicKey = keys.publicKey;
    }
  } catch (error) {
    logger.error('Failed to initialize signing keys:', error);
    throw new Error('Key initialization failed');
  }
};

export const generateTokens = (payload: TokenPayloadAuth): JWTTokens => {
  try {
    const accessToken = jwt.sign(payload, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn as StringValue,
    });

    const refreshToken = jwt.sign(payload, config.jwtSecret, {
      expiresIn: config.jwtRefreshExpiresIn as StringValue,
    });

    const expiresIn = Number(config.jwtExpiresIn);

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  } catch (error) {
    logger.error('Token generation error:', error);
    throw new Error('Failed to generate tokens');
  }
};

/**
 * Generate OIDC ID Token
 * Signed with RS256 for OIDC compliance
 */
export const generateIDToken = (claims: IDTokenClaims): string => {
  try {
    if (!privateKey) {
      initializeKeys();
    }

    return jwt.sign(claims, privateKey, {
      algorithm: 'RS256',
      expiresIn: '1h',
    });
  } catch (error) {
    logger.error('ID token generation error:', error);
    throw new Error('Failed to generate ID token');
  }
};

/**
 * Verify OIDC ID Token
 */
export const verifyIDToken = (token: string): IDTokenClaims => {
  try {
    if (!publicKey) {
      initializeKeys();
    }

    return jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as IDTokenClaims;
  } catch (error) {
    throw new Error('Invalid ID token');
  }
};

/**
 * Get public key for JWKS endpoint
 */
export const getPublicKey = (): string => {
  if (!publicKey) {
    initializeKeys();
  }
  return publicKey;
};

/**
 * Get JWKS (JSON Web Key Set) for OIDC discovery
 */
export const getJWKS = (): any => {
  if (!publicKey) {
    initializeKeys();
  }

  // Convert PEM to JWK format (simplified)
  const keyId = crypto.createHash('sha256').update(publicKey).digest('hex').substring(0, 16);

  return {
    keys: [
      {
        kty: 'RSA',
        use: 'sig',
        kid: keyId,
        alg: 'RS256',
        // In production, include full JWK components (n, e)
        // This requires parsing the PEM key
      },
    ],
  };
};

export const verifyAccessToken = (token: string): TokenPayload => {
  try {
    return jwt.verify(token, config.jwtSecret) as TokenPayload;
  } catch (error) {
    throw new Error('Invalid access token');
  }
};

export const verifyRefreshToken = (token: string): TokenPayload => {
  try {
    return jwt.verify(token, config.jwtSecret) as TokenPayload;
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};

import {
  boolean,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';
import { relations, sql } from 'drizzle-orm';
import { users } from './users';

/**
 * OAuth 2.0 Clients
 * Registered applications that can request tokens
 */
export const oauthClients = pgTable(
  'oauth_clients',
  {
    id: uuid('id')
      .default(sql`gen_random_uuid()`)
      .primaryKey(),
    clientId: varchar('client_id', { length: 255 }).notNull().unique(),
    clientSecret: varchar('client_secret', { length: 255 }).notNull(),
    clientName: varchar('client_name', { length: 255 }).notNull(),
    clientDescription: text('client_description'),
    redirectUris: jsonb('redirect_uris').notNull().$type<string[]>(),
    allowedScopes: jsonb('allowed_scopes').notNull().$type<string[]>(),
    grantTypes: jsonb('grant_types').notNull().$type<string[]>(),
    responseTypes: jsonb('response_types').notNull().$type<string[]>(),
    isConfidential: boolean('is_confidential').default(true).notNull(),
    isActive: boolean('is_active').default(true).notNull(),
    createdAt: timestamp('created_at', { mode: 'string' }).defaultNow(),
    updatedAt: timestamp('updated_at', { mode: 'string' }).defaultNow(),
  },
  (t) => ({
    idxClientId: index('idx_oauth_clients_client_id').on(t.clientId),
    idxActive: index('idx_oauth_clients_active').on(t.isActive),
  })
);

/**
 * Authorization Codes
 * PKCE-enabled authorization codes for OAuth flow
 */
export const authorizationCodes = pgTable(
  'authorization_codes',
  {
    id: uuid('id')
      .default(sql`gen_random_uuid()`)
      .primaryKey(),
    code: varchar('code', { length: 255 }).notNull().unique(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    redirectUri: text('redirect_uri').notNull(),
    scope: text('scope'),
    codeChallenge: varchar('code_challenge', { length: 255 }),
    codeChallengeMethod: varchar('code_challenge_method', { length: 10 }),
    nonce: varchar('nonce', { length: 255 }),
    expiresAt: timestamp('expires_at', { mode: 'string' }).notNull(),
    used: boolean('used').default(false).notNull(),
    createdAt: timestamp('created_at', { mode: 'string' }).defaultNow(),
  },
  (t) => ({
    idxCode: index('idx_auth_codes_code').on(t.code),
    idxUserId: index('idx_auth_codes_user_id').on(t.userId),
    idxClientId: index('idx_auth_codes_client_id').on(t.clientId),
    idxExpiresAt: index('idx_auth_codes_expires_at').on(t.expiresAt),
  })
);

/**
 * Refresh Tokens
 * With rotation support for enhanced security
 */
export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id')
      .default(sql`gen_random_uuid()`)
      .primaryKey(),
    token: varchar('token', { length: 255 }).notNull().unique(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    clientId: varchar('client_id', { length: 255 }).notNull(),
    scope: text('scope'),
    expiresAt: timestamp('expires_at', { mode: 'string' }).notNull(),
    rotatedFrom: varchar('rotated_from', { length: 255 }),
    reused: boolean('reused').default(false).notNull(),
    revokedAt: timestamp('revoked_at', { mode: 'string' }),
    createdAt: timestamp('created_at', { mode: 'string' }).defaultNow(),
  },
  (t) => ({
    idxToken: index('idx_refresh_tokens_token').on(t.token),
    idxUserId: index('idx_refresh_tokens_user_id').on(t.userId),
    idxClientId: index('idx_refresh_tokens_client_id').on(t.clientId),
    idxExpiresAt: index('idx_refresh_tokens_expires_at').on(t.expiresAt),
  })
);

/**
 * Access Token Blacklist
 * For revoked tokens (can also use Redis for this)
 */
export const accessTokenBlacklist = pgTable(
  'access_token_blacklist',
  {
    id: uuid('id')
      .default(sql`gen_random_uuid()`)
      .primaryKey(),
    tokenHash: varchar('token_hash', { length: 255 }).notNull().unique(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'cascade' }),
    clientId: varchar('client_id', { length: 255 }),
    scope: text('scope'),
    expiresAt: timestamp('expires_at', { mode: 'string' }).notNull(),
    reason: varchar('reason', { length: 255 }),
    revokedAt: timestamp('revoked_at', { mode: 'string' }).defaultNow(),
  },
  (t) => ({
    idxTokenHash: index('idx_token_blacklist_hash').on(t.tokenHash),
    idxUserId: index('idx_token_blacklist_user_id').on(t.userId),
    idxExpiresAt: index('idx_token_blacklist_expires_at').on(t.expiresAt),
  })
);

/**
 * Audit Logs
 * Comprehensive security event logging
 */
export const auditLogs = pgTable(
  'audit_logs',
  {
    id: uuid('id')
      .default(sql`gen_random_uuid()`)
      .primaryKey(),
    eventType: varchar('event_type', { length: 100 }).notNull(),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    clientId: varchar('client_id', { length: 255 }),
    serviceId: varchar('service_id', { length: 255 }),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    resource: varchar('resource', { length: 255 }),
    action: varchar('action', { length: 100 }),
    scope: text('scope'),
    success: boolean('success').notNull(),
    details: jsonb('details'),
    errorMessage: text('error_message'),
    requestId: varchar('request_id', { length: 255 }),
    sessionId: varchar('session_id', { length: 255 }),
    trustScore: integer('trust_score'),
    riskFactors: jsonb('risk_factors').$type<string[]>(),
    createdAt: timestamp('created_at', { mode: 'string' }).defaultNow(),
  },
  (t) => ({
    idxEventType: index('idx_audit_logs_event_type').on(t.eventType),
    idxUserId: index('idx_audit_logs_user_id').on(t.userId),
    idxClientId: index('idx_audit_logs_client_id').on(t.clientId),
    idxCreatedAt: index('idx_audit_logs_created_at').on(t.createdAt),
    idxRequestId: index('idx_audit_logs_request_id').on(t.requestId),
  })
);



/**
 * Relations
 */
export const authorizationCodesRelations = relations(authorizationCodes, ({ one }) => ({
  user: one(users, {
    fields: [authorizationCodes.userId],
    references: [users.id],
  }),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, {
    fields: [refreshTokens.userId],
    references: [users.id],
  }),
}));

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, {
    fields: [auditLogs.userId],
    references: [users.id],
  }),
}));

/**
 * OAuth 2.0 Client Seed Script
 * Registers all service clients and a test client in the oauth_clients table.
 * Run with: pnpm tsx src/seeds/seed-oauth-clients.ts
 */
import dotenv from 'dotenv';
dotenv.config({ path: '../../../.env' }); // root .env

import { db } from '../index';
import { oauthClients } from '../schemas/oauth';
import { eq } from 'drizzle-orm';

const SERVICE_CLIENTS = [
  {
    clientId: 'course-service',
    clientSecret: 'course-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Course Service',
    clientDescription: 'Internal microservice for course management',
    redirectUris: [] as string[],
    allowedScopes: ['courses:read', 'courses:write', 'users:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'payment-service',
    clientSecret: 'payment-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Payment Service',
    clientDescription: 'Internal microservice for payment processing',
    redirectUris: [] as string[],
    allowedScopes: ['payments', 'users:read', 'courses:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'assessment-service',
    clientSecret: 'assessment-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Assessment Service',
    clientDescription: 'Internal microservice for assessments and quizzes',
    redirectUris: [] as string[],
    allowedScopes: ['assessments:read', 'assessments:write', 'users:read', 'courses:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'analytics-service',
    clientSecret: 'analytics-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Analytics Service',
    clientDescription: 'Internal microservice for analytics and reporting',
    redirectUris: [] as string[],
    allowedScopes: ['users:read', 'courses:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'notification-service',
    clientSecret: 'notification-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Notification Service',
    clientDescription: 'Internal microservice for notifications',
    redirectUris: [] as string[],
    allowedScopes: ['users:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'live-session-service',
    clientSecret: 'live-session-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'Live Session Service',
    clientDescription: 'Internal microservice for live sessions',
    redirectUris: [] as string[],
    allowedScopes: ['users:read', 'courses:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'file-service',
    clientSecret: 'file-service_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'File Service',
    clientDescription: 'Internal microservice for file storage',
    redirectUris: [] as string[],
    allowedScopes: ['users:read'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  {
    clientId: 'api-gateway',
    clientSecret: 'api-gateway_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'API Gateway',
    clientDescription: 'API Gateway service',
    redirectUris: [] as string[],
    allowedScopes: ['users:read', 'courses:read', 'payments', 'assessments:read', 'assessments:write'],
    grantTypes: ['client_credentials'],
    responseTypes: ['token'],
    isConfidential: true,
    isActive: true,
  },
  // Test web client (authorization code + PKCE flow)
  {
    clientId: 'lms-web-client',
    clientSecret: 'lms-web-client_g7qMhbliy1fiMCStqr6HJ7OQ',
    clientName: 'LMS Web Application',
    clientDescription: 'Frontend web application client',
    redirectUris: ['http://localhost:3000/auth/callback', 'http://localhost:5173/auth/callback'],
    allowedScopes: ['openid', 'profile', 'email', 'courses:read', 'courses:write', 'assessments:read', 'assessments:write', 'payments'],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
    isConfidential: false,
    isActive: true,
  },
];

async function seedOAuthClients() {
  console.log('🔐 Seeding OAuth clients...\n');

  let inserted = 0;
  let skipped = 0;

  for (const client of SERVICE_CLIENTS) {
    const existing = await db
      .select({ clientId: oauthClients.clientId })
      .from(oauthClients)
      .where(eq(oauthClients.clientId, client.clientId))
      .limit(1);

    if (existing.length > 0) {
      // Update secret/scopes in case they changed
      await db
        .update(oauthClients)
        .set({
          clientSecret: client.clientSecret,
          allowedScopes: client.allowedScopes,
          isActive: client.isActive,
        })
        .where(eq(oauthClients.clientId, client.clientId));
      console.log(`  ↺  Updated:  ${client.clientId}`);
      skipped++;
    } else {
      await db.insert(oauthClients).values(client);
      console.log(`  ✅ Inserted: ${client.clientId}`);
      inserted++;
    }
  }

  console.log(`\n✅ Done — ${inserted} inserted, ${skipped} updated.`);
  process.exit(0);
}

seedOAuthClients().catch((err) => {
  console.error('❌ Seed failed:', err);
  process.exit(1);
});

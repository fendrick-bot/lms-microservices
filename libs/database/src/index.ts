import dotenv from 'dotenv';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';

// Load environment variables
dotenv.config();

// Database connection
const connectionString =
  process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/lms_db';

// Create PostgreSQL connection pool
export const pool = new Pool({
  connectionString,
});

// For drizzle
export const db = drizzle(pool);

// Export schemas
export * from './schemas/users';
export * from './schemas/categories';
export * from './schemas/reviews';
export * from './schemas/payments';
export * from './schemas/live-sessions';
export * from './schemas/proctoring';
export * from './schemas/assessments';
export * from './schemas/courses';
export * from './schemas/enrollments';
export * from './schemas/notifications';
export * from './schemas/settings';
export * from './schemas/file';
export * from './schemas/oauth';

// Export utilities
export * from './utils/password-hash';

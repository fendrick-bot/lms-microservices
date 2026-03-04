dotenv.config();
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { errorHandler } from '@lms/common';
import { logger } from '@lms/logger';
import { initFirebase } from './config/firebase';
import { authRoutes } from './routes/auth.routes';
import { authVerificationRoutes } from './routes/auth-verification.routes';
import userRoutes from './routes/user.routes';
import oauthRoutes from './routes/oauth.routes';

initFirebase();

const app = express();
const PORT = process.env.USER_SERVICE_PORT || 3001;

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: '*',
    credentials: true,
  })
);
app.use(compression());
app.use(morgan('combined'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
// TODO: Add user routes

// Health check
app.get('/health', async (req, res) => {
  // const user = await db.select().from(users);
  // console.log(user);
  res.json({
    status: 'OK',
    // data: user,
    service: 'User Service',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});
app.use('/api/auth', authRoutes);
app.use('/api/auth-verification', authVerificationRoutes);
app.use('/api/users', userRoutes);

// OAuth 2.0 / OIDC routes (mounted at root for standard paths)
app.use('/', oauthRoutes);



// Global error handler
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  logger.info(`User Service running on port ${PORT}`);
});
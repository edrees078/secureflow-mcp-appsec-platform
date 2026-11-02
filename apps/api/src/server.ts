import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './logger/logger.js';
import { createDomainServices } from '@secureflow/domain';

// Initialize production domain services container through the approved composition root
const domainServices = createDomainServices({
  connectionString: env.DATABASE_URL,
});

const app = createApp(domainServices);

const server = app.listen(env.PORT, () => {
  logger.info(
    {
      port: env.PORT,
      nodeEnv: env.NODE_ENV,
      logLevel: env.LOG_LEVEL,
      corsOrigin: env.CORS_ORIGIN,
    },
    'SecureFlow API server listening'
  );
});

async function gracefulShutdown(signal: string): Promise<void> {
  logger.info({ signal }, 'Received shutdown signal, closing HTTP server gracefully...');
  server.close(async (err) => {
    if (err) {
      logger.error({ err }, 'Error during HTTP server close');
      process.exit(1);
    }
    try {
      await domainServices.close();
      logger.info('Domain services connection pool closed successfully');
      logger.info('HTTP server closed successfully');
      process.exit(0);
    } catch (closeErr) {
      logger.error({ err: closeErr }, 'Error closing domain services connection pool');
      process.exit(1);
    }
  });

  // Force shutdown after 10 seconds timeout
  setTimeout(() => {
    logger.error('Forced shutdown timeout reached, exiting process');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => void gracefulShutdown('SIGINT'));

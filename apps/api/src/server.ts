import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './logger/logger.js';

const app = createApp();

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

function gracefulShutdown(signal: string) {
  logger.info({ signal }, 'Received shutdown signal, closing HTTP server gracefully...');
  server.close((err) => {
    if (err) {
      logger.error({ err }, 'Error during HTTP server close');
      process.exit(1);
    }
    logger.info('HTTP server closed successfully');
    process.exit(0);
  });

  // Force shutdown after 10 seconds timeout
  setTimeout(() => {
    logger.error('Forced shutdown timeout reached, exiting process');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

/**
 * Internal Domain Database Module.
 *
 * Exposes DatabaseManager, PostgreSQL connection lifecycle, and repository implementations.
 * Under architectural boundary rules (docs/02-architecture.md, eslint.config.mjs),
 * this module is strictly internal to packages/domain and MUST NOT be imported
 * directly by apps/api or apps/mcp-server.
 */
export { FindingRepository } from './finding-repository.js';
export { verifyDatabaseConnectivity, type DatabaseConnectivityResult } from './smoke-check.js';
export {
  DatabaseManager,
  type DatabaseConfig,
  type DatabaseIdentity,
  redactDatabaseUrl,
} from './database-manager.js';
export * from './repositories/index.js';

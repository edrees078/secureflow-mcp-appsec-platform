import type { RepositoryContainer } from '../db/repositories/types.js';

/**
 * Internal unexported symbol used to authorize test persistence injection.
 * Only @secureflow/domain/testing can access this token.
 * Ordinary production consumers cannot import or construct this token.
 */
export const TEST_PERSISTENCE_TOKEN: unique symbol = Symbol('TEST_PERSISTENCE_TOKEN');

export interface TestPersistenceWrapper {
  readonly [TEST_PERSISTENCE_TOKEN]: true;
  readonly repositories: RepositoryContainer;
}

export function isAuthorizedTestPersistence(
  value: unknown,
): value is TestPersistenceWrapper {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<symbol, unknown>)[TEST_PERSISTENCE_TOKEN] === true &&
    'repositories' in value &&
    typeof (value as Record<string, unknown>)['repositories'] === 'object' &&
    (value as Record<string, unknown>)['repositories'] !== null
  );
}

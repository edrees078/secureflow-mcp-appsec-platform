import { describe, it, expect, vi } from 'vitest';
import {
  DatabaseManager,
  redactDatabaseUrl,
} from '../../src/db/database-manager.js';
import { validateTestDatabaseUrl } from '../integration/gate3b-repositories.integration.js';
import { SecureFlowError } from '@secureflow/shared';

describe('Gate 3B — DatabaseManager Lifecycle & Configuration (Offline Unit Tests)', () => {
  const validDevUrl = 'postgresql://secureflow:super_secret_dev_pass@127.0.0.1:5433/secureflow_dev?schema=public';
  const validTestUrl = 'postgresql://secureflow:super_secret_test_pass@127.0.0.1:5433/secureflow_test?schema=public';

  describe('Configuration & Password Redaction', () => {
    it('redactDatabaseUrl masks password and leaves host/port/db intact', () => {
      const redacted = redactDatabaseUrl(validDevUrl);
      expect(redacted).not.toContain('super_secret_dev_pass');
      expect(redacted).toContain('****');
      expect(redacted).toContain('127.0.0.1:5433');
      expect(redacted).toContain('secureflow_dev');
    });

    it('redactDatabaseUrl safely handles URLs without passwords', () => {
      const noPass = 'postgresql://127.0.0.1:5433/secureflow_dev';
      expect(redactDatabaseUrl(noPass)).toBe(noPass);
    });

    it('redactDatabaseUrl safely handles malformed URLs without throwing', () => {
      const malformed = 'not-a-valid-url';
      expect(redactDatabaseUrl(malformed)).toBe('postgresql://[REDACTED_INVALID_URL]');
    });

    it('DatabaseManager rejects missing or empty connection string', () => {
      expect(() => new DatabaseManager({ connectionString: '' })).toThrow(SecureFlowError);
      expect(() => new DatabaseManager({ connectionString: null as unknown as string })).toThrow(SecureFlowError);
    });

    it('DatabaseManager rejects malformed connection URLs', () => {
      expect(() => new DatabaseManager({ connectionString: 'invalid-url' })).toThrow(SecureFlowError);
    });

    it('DatabaseManager rejects non-PostgreSQL protocols', () => {
      expect(() => new DatabaseManager({ connectionString: 'mysql://user:pass@127.0.0.1:3306/db' })).toThrow(
        SecureFlowError,
      );
      expect(() => new DatabaseManager({ connectionString: 'http://127.0.0.1:8080/db' })).toThrow(SecureFlowError);
    });

    it('DatabaseManager parses target database, host, and port correctly', () => {
      const mgr = new DatabaseManager({ connectionString: validDevUrl });
      expect(mgr.targetDatabase).toBe('secureflow_dev');
      expect(mgr.targetHost).toBe('127.0.0.1');
      expect(mgr.targetPort).toBe(5433);
      expect(mgr.targetSchema).toBe('public');
      expect(mgr.redactedUrl).not.toContain('super_secret_dev_pass');
      expect(mgr.redactedUrl).toContain('****');
    });
  });

  describe('Instance Isolation (No Mutable Singletons)', () => {
    it('separate instances maintain independent configurations and targets', () => {
      const devMgr = new DatabaseManager({ connectionString: validDevUrl });
      const testMgr = new DatabaseManager({ connectionString: validTestUrl });

      expect(devMgr.targetDatabase).toBe('secureflow_dev');
      expect(testMgr.targetDatabase).toBe('secureflow_test');
      expect(devMgr.getPool()).not.toBe(testMgr.getPool());
      expect(devMgr.getPrismaClient()).not.toBe(testMgr.getPrismaClient());
    });
  });

  describe('Lifecycle & Deterministic Graceful Shutdown', () => {
    it('shutdown is idempotent and safe to invoke multiple times without double-closing pool', async () => {
      const mgr = new DatabaseManager({ connectionString: validDevUrl });
      const pool = mgr.getPool();
      const prisma = mgr.getPrismaClient();

      const poolEndSpy = vi.spyOn(pool, 'end');
      const prismaDisconnectSpy = vi.spyOn(prisma, '$disconnect');

      await mgr.shutdown();
      expect(poolEndSpy).toHaveBeenCalledTimes(1);
      expect(prismaDisconnectSpy).toHaveBeenCalledTimes(1);

      // Second shutdown must be a no-op: neither pool.end nor prisma.$disconnect is called again
      await mgr.shutdown();
      expect(poolEndSpy).toHaveBeenCalledTimes(1);
      expect(prismaDisconnectSpy).toHaveBeenCalledTimes(1);
    });

    it('getPrismaClient and getPool throw SecureFlowError after shutdown', async () => {
      const mgr = new DatabaseManager({ connectionString: validDevUrl });
      await mgr.shutdown();

      expect(() => mgr.getPrismaClient()).toThrow(SecureFlowError);
      expect(() => mgr.getPool()).toThrow(SecureFlowError);
      expect(() => mgr.getRepositories()).toThrow(SecureFlowError);
    });

    it('runTransaction rejects after shutdown', async () => {
      const mgr = new DatabaseManager({ connectionString: validDevUrl });
      await mgr.shutdown();

      await expect(mgr.runTransaction(async () => 'ok')).rejects.toThrow(SecureFlowError);
    });
  });

  describe('Database Test Isolation Safety Rules (validateTestDatabaseUrl)', () => {
    it('NEGATIVE: refuses when TEST_DATABASE_URL is absent or empty', () => {
      expect(() => validateTestDatabaseUrl(undefined)).toThrowError(
        /SAFETY REFUSAL: TEST_DATABASE_URL is required/,
      );
      expect(() => validateTestDatabaseUrl('')).toThrowError(
        /SAFETY REFUSAL: TEST_DATABASE_URL is required/,
      );
    });

    it('NEGATIVE: refuses when TEST_DATABASE_URL targets secureflow_dev', () => {
      expect(() =>
        validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5433/secureflow_dev'),
      ).toThrowError(/SAFETY REFUSAL: TEST_DATABASE_URL must NEVER target development database "secureflow_dev"/);
    });

    it('NEGATIVE: refuses when TEST_DATABASE_URL targets any database other than secureflow_test', () => {
      expect(() =>
        validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5433/other_db'),
      ).toThrowError(/SAFETY REFUSAL: TEST_DATABASE_URL must target "secureflow_test"/);
    });

    it('NEGATIVE: refuses when TEST_DATABASE_URL targets native PostgreSQL 15 on port 5432', () => {
      expect(() =>
        validateTestDatabaseUrl('postgresql://secureflow:pass@127.0.0.1:5432/secureflow_test'),
      ).toThrowError(/SAFETY REFUSAL: TEST_DATABASE_URL targets port 5432 \(native PostgreSQL 15\)/);
    });

    it('POSITIVE: accepts valid secureflow_test URL on port 5433', () => {
      const valid = 'postgresql://secureflow:pass@127.0.0.1:5433/secureflow_test?schema=public';
      expect(validateTestDatabaseUrl(valid)).toBe(valid);
    });
  });
});

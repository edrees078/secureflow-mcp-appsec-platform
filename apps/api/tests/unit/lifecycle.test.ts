import { describe, it, expect } from 'vitest';
import { createDomainServices } from '@secureflow/domain';

describe('Domain Services Composition & Shutdown Lifecycle', () => {
  it('instantiates all 4 domain services and closes connection pool when owned', async () => {
    const config = {
      connectionString: 'postgresql://secureflow:secureflow_dev_password_change_me@127.0.0.1:5433/secureflow_dev?schema=public',
    };

    const services = createDomainServices(config);

    expect(services.projectService).toBeDefined();
    expect(services.auditService).toBeDefined();
    expect(services.findingService).toBeDefined();
    expect(services.taskService).toBeDefined();
    expect(typeof services.close).toBe('function');

    // Calling close on owned instance shuts down the pool cleanly
    await expect(services.close()).resolves.toBeUndefined();
  });

  it('rejects null or undefined configuration with SERVICE_INITIALIZATION_ERROR', () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect(() => createDomainServices(null as any)).toThrow(
      /createDomainServices failed/
    );
  });
});

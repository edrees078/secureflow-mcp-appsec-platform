import type { ActorContext } from '@secureflow/domain';

declare global {
  namespace Express {
    interface Request {
      id?: string;
      actor?: ActorContext;
      sessionId?: string;
      sessionCsrfToken?: string;
      validated?: {
        body?: unknown;
        query?: unknown;
        params?: unknown;
      };
    }
  }
}

export {};

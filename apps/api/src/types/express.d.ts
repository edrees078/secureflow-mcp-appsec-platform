import type { ActorContext } from '@secureflow/domain';

declare global {
  namespace Express {
    interface Request {
      id?: string;
      actor?: ActorContext;
      validated?: {
        body?: unknown;
        query?: unknown;
        params?: unknown;
      };
    }
  }
}

export {};

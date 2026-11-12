import type { ActorContext, UserProfileEntity } from '@secureflow/domain';

declare global {
  namespace Express {
    interface Request {
      id?: string;
      actor?: ActorContext;
      user?: UserProfileEntity;
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

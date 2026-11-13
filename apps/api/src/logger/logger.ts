import pino from 'pino';
import { env } from '../config/env.js';
import {
  sanitizeAuditStateValue,
  sanitizeStringCredentialPatterns,
} from '../routes/v1/audit-events.js';

export const SENSITIVE_REDACTION_PATHS = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["set-cookie"]',
  'req.headers["x-csrf-token"]',
  'res.headers["set-cookie"]',
  'req.query.code',
  'req.query.state',
  'req.query.nonce',
  'req.query.session_state',
  'req.query.id_token_hint',
  'req.query.logout_token',
  'req.query.code_verifier',
  'req.query.client_secret',
  'req.query.access_token',
  'req.query.refresh_token',
  'req.query.id_token',
  'headers.authorization',
  'headers.cookie',
  'headers["set-cookie"]',
  'headers["x-csrf-token"]',
  'authorization',
  'cookie',
  'set-cookie',
  'password',
  '*.password',
  '*.*.password',
  'token',
  '*.token',
  '*.*.token',
  'secret',
  '*.secret',
  '*.*.secret',
  'idToken',
  '*.idToken',
  '*.*.idToken',
  'refreshToken',
  '*.refreshToken',
  '*.*.refreshToken',
  'accessToken',
  '*.accessToken',
  '*.*.accessToken',
  'authorizationCode',
  '*.authorizationCode',
  '*.*.authorizationCode',
  'codeVerifier',
  '*.codeVerifier',
  '*.*.codeVerifier',
  'pkceCodeVerifier',
  '*.pkceCodeVerifier',
  '*.*.pkceCodeVerifier',
  'sessionId',
  '*.sessionId',
  '*.*.sessionId',
  'sessionToken',
  '*.sessionToken',
  '*.*.sessionToken',
  'rawSessionToken',
  '*.rawSessionToken',
  '*.*.rawSessionToken',
  'rawTxnToken',
  '*.rawTxnToken',
  '*.*.rawTxnToken',
  'csrfToken',
  '*.csrfToken',
  '*.*.csrfToken',
  'sessionSecret',
  '*.sessionSecret',
  '*.*.sessionSecret',
  'clientSecret',
  '*.clientSecret',
  '*.*.clientSecret',
  'databaseUrl',
  '*.databaseUrl',
  '*.*.databaseUrl',
  'connectionString',
  '*.connectionString',
  '*.*.connectionString',
  'apiKey',
  '*.apiKey',
  '*.*.apiKey',
];

function sanitizeErrorInstance(origErr: Error): Error {
  const safeMsg = sanitizeStringCredentialPatterns(origErr.message);
  const safeStack = origErr.stack
    ? sanitizeStringCredentialPatterns(origErr.stack)
    : undefined;
  if (safeMsg === origErr.message && safeStack === origErr.stack) {
    return origErr;
  }
  const redactedErr = new Error(safeMsg);
  redactedErr.name = origErr.name;
  if (safeStack !== undefined) {
    redactedErr.stack = safeStack;
  }
  return redactedErr;
}

export const SENSITIVE_HTTP_QUERY_KEYS: ReadonlySet<string> = new Set([
  'code',
  'state',
  'nonce',
  'sessionstate',
  'idtokenhint',
  'logouttoken',
  'authorizationcode',
  'codeverifier',
  'clientsecret',
  'accesstoken',
  'refreshtoken',
  'idtoken',
  'csrftoken',
]);

const SENSITIVE_HTTP_HEADER_KEYS: ReadonlySet<string> = new Set([
  'authorization',
  'proxyauthorization',
  'cookie',
  'setcookie',
  'xcsrftoken',
]);

function isNodeServerResponse(value: unknown): value is {
  readonly statusCode: number;
  readonly headersSent: boolean;
  readonly getHeader: (name: string) => unknown;
  readonly getHeaders?: () => Record<string, unknown>;
} {
  return (
    value !== null &&
    typeof value === 'object' &&
    typeof (value as { getHeader?: unknown }).getHeader === 'function'
  );
}

export function sanitizeHttpHeaders(headers: unknown): unknown {
  if (headers === null || headers === undefined || typeof headers !== 'object' || Array.isArray(headers)) {
    return headers;
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(headers as Record<string, unknown>)) {
    const normalizedKey = key.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (SENSITIVE_HTTP_HEADER_KEYS.has(normalizedKey)) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof val === 'string') {
      sanitized[key] = sanitizeStringCredentialPatterns(val);
    } else if (Array.isArray(val)) {
      sanitized[key] = val.map((item) =>
        typeof item === 'string'
          ? sanitizeStringCredentialPatterns(item)
          : sanitizeAuditStateValue(item, 1),
      );
    } else if (val !== null && typeof val === 'object') {
      sanitized[key] = sanitizeAuditStateValue(val, 1);
    } else {
      sanitized[key] = val;
    }
  }
  return sanitized;
}

export function sanitizeHttpQuery(query: unknown): unknown {
  if (query === null || query === undefined || typeof query !== 'object' || Array.isArray(query)) {
    return query;
  }

  const redactedQuery: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(query as Record<string, unknown>)) {
    const norm = k.toLowerCase().replace(/[^a-z0-9]/g, '');
    if (SENSITIVE_HTTP_QUERY_KEYS.has(norm)) {
      redactedQuery[k] = '[REDACTED]';
    } else if (typeof v === 'string') {
      redactedQuery[k] = sanitizeStringCredentialPatterns(v);
    } else if (v !== null && typeof v === 'object') {
      redactedQuery[k] = sanitizeAuditStateValue(v, 1);
    } else {
      redactedQuery[k] = v;
    }
  }
  return redactedQuery;
}

export function sanitizeSerializedRequest(reqObj: unknown): unknown {
  if (reqObj === null || reqObj === undefined || typeof reqObj !== 'object' || Array.isArray(reqObj)) {
    return reqObj;
  }

  const record = reqObj as Record<string, unknown>;
  const url =
    typeof record['url'] === 'string'
      ? sanitizeStringCredentialPatterns(record['url'])
      : record['url'];
  const query =
    'query' in record ? sanitizeHttpQuery(record['query']) : record['query'];
  const headers =
    'headers' in record ? sanitizeHttpHeaders(record['headers']) : record['headers'];

  return {
    ...record,
    ...('url' in record ? { url } : {}),
    ...('query' in record ? { query } : {}),
    ...('headers' in record ? { headers } : {}),
  };
}

export function sanitizeSerializedResponse(resObj: unknown): unknown {
  if (resObj === null || resObj === undefined || typeof resObj !== 'object' || Array.isArray(resObj)) {
    return resObj;
  }

  if (isNodeServerResponse(resObj)) {
    const rawHeaders =
      typeof resObj.getHeaders === 'function' ? resObj.getHeaders() : {};
    return {
      statusCode: resObj.headersSent ? resObj.statusCode : null,
      headers: sanitizeHttpHeaders(rawHeaders),
    };
  }

  const record = resObj as Record<string, unknown>;
  const headers =
    'headers' in record ? sanitizeHttpHeaders(record['headers']) : record['headers'];

  return {
    ...record,
    ...('headers' in record ? { headers } : {}),
  };
}

export function sanitizeLogPayload(
  payload: Record<string, unknown>,
): Record<string, unknown> {
  // Preserve native Node IncomingMessage / ServerResponse instances so serializers run intact
  const rawReq = payload['req'];
  const rawRes = payload['res'];
  const preserveRes = isNodeServerResponse(rawRes);

  const sanitizedInput = preserveRes ? { ...payload, res: undefined } : payload;
  const sanitized = sanitizeAuditStateValue(sanitizedInput, 0) as Record<
    string,
    unknown
  >;
  if (preserveRes) {
    sanitized['res'] = rawRes;
  } else if (rawRes === undefined && !('res' in payload)) {
    delete sanitized['res'];
  }

  const reqObj = sanitized['req'] ?? (typeof rawReq === 'object' ? rawReq : undefined);
  if (reqObj && typeof reqObj === 'object' && !Array.isArray(reqObj)) {
    sanitized['req'] = sanitizeSerializedRequest(reqObj);
  }
  if (!preserveRes && sanitized['res'] && typeof sanitized['res'] === 'object') {
    sanitized['res'] = sanitizeSerializedResponse(sanitized['res']);
  }
  if (payload['err'] instanceof Error) {
    sanitized['err'] = sanitizeErrorInstance(payload['err']);
  }
  return sanitized;
}

export function createLogger(
  logLevel = env.LOG_LEVEL,
  destination?: pino.DestinationStream,
) {
  const options: pino.LoggerOptions = {
    level: logLevel,
    redact: {
      paths: SENSITIVE_REDACTION_PATHS,
      censor: '[REDACTED]',
    },
    serializers: {
      req: sanitizeSerializedRequest,
      res: sanitizeSerializedResponse,
      headers: sanitizeHttpHeaders,
    },
    hooks: {
      logMethod(inputArgs, method) {
        const sanitizedArgs = inputArgs.map((arg, index) => {
          if (typeof arg === 'string') {
            return sanitizeStringCredentialPatterns(arg);
          }
          if (
            index === 0 &&
            arg !== null &&
            typeof arg === 'object' &&
            !Array.isArray(arg) &&
            'err' in arg &&
            (arg as { err?: unknown }).err instanceof Error
          ) {
            return {
              ...(arg as Record<string, unknown>),
              err: sanitizeErrorInstance((arg as { err: Error }).err),
            };
          }
          return arg;
        });
        return method.apply(this, sanitizedArgs as Parameters<typeof method>);
      },
    },
    formatters: {
      level(label) {
        return { level: label };
      },
      log(object) {
        return sanitizeLogPayload(object);
      },
    },
    timestamp: pino.stdTimeFunctions.isoTime,
  };

  return destination ? pino(options, destination) : pino(options);
}

export const logger = createLogger();

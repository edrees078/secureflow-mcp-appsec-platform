import { describe, it, expect } from 'vitest';
import {
  COOKIE_NAME_DEV_OIDC_TXN,
  COOKIE_NAME_DEV_SESSION,
  COOKIE_NAME_PRODUCTION_OIDC_TXN,
  COOKIE_NAME_PRODUCTION_SESSION,
  clearOidcTxnCookie,
  clearSessionCookie,
  extractNamedCookie,
  parseCookieHeader,
  readOidcTxnCookie,
  readSessionCookie,
  resolveCookieProfile,
  serializeCookie,
  serializeOidcTxnCookie,
  serializeSessionCookie,
} from '../../src/auth/cookies.js';

describe('Gate 4B.2 Secure Cookie Primitives', () => {
  const prodProfile = resolveCookieProfile('production');
  const devProfile = resolveCookieProfile('development');

  it('enforces production __Host- cookie names and exact required attributes without Domain', () => {
    expect(prodProfile.sessionCookieName).toBe(COOKIE_NAME_PRODUCTION_SESSION);
    expect(prodProfile.oidcTxnCookieName).toBe(COOKIE_NAME_PRODUCTION_OIDC_TXN);

    const sessionHeader = serializeSessionCookie(prodProfile, 'synth_session_token_abc123', 1800);
    expect(sessionHeader).toBe(
      '__Host-sf_session=synth_session_token_abc123; Max-Age=1800; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
    expect(sessionHeader).not.toContain('Domain=');

    const txnHeader = serializeOidcTxnCookie(prodProfile, 'synth_txn_token_xyz789', 300);
    expect(txnHeader).toBe(
      '__Host-sf_oidc_txn=synth_txn_token_xyz789; Max-Age=300; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
    expect(txnHeader).not.toContain('Domain=');
  });

  it('uses unprefixed cookie names only for local HTTP development', () => {
    expect(devProfile.sessionCookieName).toBe(COOKIE_NAME_DEV_SESSION);
    expect(devProfile.oidcTxnCookieName).toBe(COOKIE_NAME_DEV_OIDC_TXN);

    const devSession = serializeSessionCookie(devProfile, 'dev_session_tok_123', 1800);
    expect(devSession).toBe(
      'sf_session=dev_session_tok_123; Max-Age=1800; Path=/; HttpOnly; SameSite=Lax',
    );
    expect(devSession).not.toContain('Secure');
    expect(devSession).not.toContain('__Host-');
  });

  it('rejects __Host- / __Secure- prefix violations and invalid syntax or expiration attributes', () => {
    expect(() => resolveCookieProfile('production', { secure: false })).toThrow(/Secure=true/);

    expect(() =>
      serializeCookie('__Host-sf_session', 'tok123', {
        secure: false,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
      }),
    ).toThrow(/__Host-/);

    expect(() =>
      serializeCookie('__Host-sf_session', 'tok123', {
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/api/v1',
      }),
    ).toThrow(/Path=\//);

    expect(() =>
      serializeCookie('__Host-sf_session', 'tok123', {
        secure: true,
        httpOnly: true,
        sameSite: 'Lax',
        path: '/',
        domain: 'app.secureflow.example',
      }),
    ).toThrow(/Domain/);

    expect(() =>
      serializeCookie('__Secure-test', 'tok123', { secure: false }),
    ).toThrow(/__Secure-/);

    expect(() => serializeCookie('bad name', 'tok123')).toThrow();
    expect(() => serializeCookie('__Host-sf_session', 'bad\r\nSet-Cookie: evil=1', {
      secure: true,
      path: '/',
    })).toThrow();
    expect(() => serializeSessionCookie(prodProfile, 'tok123', 0)).toThrow();
    expect(() => serializeSessionCookie(prodProfile, 'tok123', -10)).toThrow();
    expect(() => serializeSessionCookie(prodProfile, 'tok123', 12.5)).toThrow();
    expect(() =>
      serializeCookie('sf_session', 'tok123', { expires: new Date('not-a-date') }),
    ).toThrow(/Expires/);
  });

  it('serializes secure cookie clearing with Max-Age=0, Unix epoch Expires, and matching __Host- constraints', () => {
    const clearedSession = clearSessionCookie(prodProfile);
    expect(clearedSession).toBe(
      '__Host-sf_session=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax',
    );
    expect(clearedSession).not.toContain('Domain=');

    const clearedTxn = clearOidcTxnCookie(prodProfile);
    expect(clearedTxn).toBe(
      '__Host-sf_oidc_txn=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; Secure; SameSite=Lax',
    );

    const devCleared = clearSessionCookie(devProfile);
    expect(devCleared).toBe(
      'sf_session=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/; HttpOnly; SameSite=Lax',
    );
  });

  it('never falls back from __Host- production cookie names to unprefixed development cookie names', () => {
    const devCookieHeader = 'sf_session=attacker_dev_cookie_value; sf_oidc_txn=attacker_dev_txn';

    const prodSessionRead = readSessionCookie(devCookieHeader, prodProfile);
    expect(prodSessionRead).toEqual({
      present: false,
      status: 'missing',
      value: null,
    });

    const prodTxnRead = readOidcTxnCookie(devCookieHeader, prodProfile);
    expect(prodTxnRead).toEqual({
      present: false,
      status: 'missing',
      value: null,
    });

    expect(readSessionCookie(devCookieHeader, devProfile)).toEqual({
      present: true,
      status: 'ok',
      value: 'attacker_dev_cookie_value',
    });
  });

  it('rejects duplicate auth cookies across single or repeated Cookie headers', () => {
    const dupSingleHeader = readSessionCookie(
      '__Host-sf_session=token_one; other=1; __Host-sf_session=token_two',
      prodProfile,
    );
    expect(dupSingleHeader).toEqual({
      present: false,
      status: 'duplicate',
      value: null,
      reason: 'DUPLICATE_COOKIE',
    });

    const dupArrayHeader = readOidcTxnCookie(
      ['__Host-sf_oidc_txn=txn_one', '__Host-sf_oidc_txn=txn_one'],
      prodProfile,
    );
    expect(dupArrayHeader).toEqual({
      present: false,
      status: 'duplicate',
      value: null,
      reason: 'DUPLICATE_COOKIE',
    });
  });

  it('rejects malformed Cookie headers and invalid cookie values deterministically', () => {
    expect(parseCookieHeader('=missing_name').valid).toBe(false);
    expect(parseCookieHeader('pair_without_equals').valid).toBe(false);
    expect(parseCookieHeader('__Host-sf_session=val with space').valid).toBe(false);
    expect(parseCookieHeader('__Host-sf_session=bad\r\ninject').valid).toBe(false);

    expect(extractNamedCookie('__Host-sf_session', '__Host-sf_session').status).toBe('malformed');
    expect(extractNamedCookie('__Host-sf_session=', '__Host-sf_session').status).toBe('malformed');
    expect(
      extractNamedCookie('__Host-sf_session=good_val; __Host-sf_session=bad val', '__Host-sf_session').status,
    ).toBe('malformed');
    expect(
      extractNamedCookie('__Host-sf_session=' + 'a'.repeat(5000), '__Host-sf_session').status,
    ).toBe('malformed');
    expect(extractNamedCookie(undefined, '__Host-sf_session')).toEqual({
      present: false,
      status: 'missing',
      value: null,
    });
  });
});

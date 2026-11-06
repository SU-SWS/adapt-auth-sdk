/* eslint-disable @typescript-eslint/no-explicit-any */
import { sealData, unsealData } from 'iron-session';
import { SessionManager, CookieStore } from '../src/session';
import { EdgeSessionReader } from '../src/edge-session';
import { AuthUtils } from '../src/utils';
import { User } from '../src/types';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V8 = /^[0-9a-f]{8}-[0-9a-f]{4}-8[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const secret = 'test-secret-32-characters-long!!';
const config = { name: 'test-session', secret, cookie: {} };

const testUser: User = {
  id: 'user123',
  email: 'test@stanford.edu',
  name: 'Test User',
};

/** In-memory cookie jar so cookies written by one call are read by the next */
function createJar(initial: Record<string, string> = {}): CookieStore & { values: Map<string, string> } {
  const values = new Map(Object.entries(initial));
  return {
    values,
    get: (name) => (values.has(name) ? { name, value: values.get(name)! } : undefined),
    set: (name, value) => {
      if (value) values.set(name, value);
      else values.delete(name);
    },
    delete: (name) => {
      values.delete(name);
    },
  };
}

/** Read the raw sealed contents of the session cookie */
async function readCookie(jar: ReturnType<typeof createJar>): Promise<any> {
  return unsealData(jar.values.get(config.name)!, { password: secret });
}

describe('Session IDs', () => {
  describe('new sessions', () => {
    it('createSession assigns a UUID v4 and seals it into the cookie', async () => {
      const jar = createJar();
      const session = await new SessionManager(jar, config).createSession(testUser);

      expect(session.id).toMatch(UUID_V4);
      expect((await readCookie(jar)).id).toBe(session.id);
    });

    it('issues a new ID on every login', async () => {
      const manager = new SessionManager(createJar(), config);

      const first = await manager.createSession(testUser);
      const second = await manager.createSession(testUser);

      expect(second.id).not.toBe(first.id);
    });

    it('getSession returns the sealed ID', async () => {
      const jar = createJar();
      const manager = new SessionManager(jar, config);
      const created = await manager.createSession(testUser);

      expect((await manager.getSession())?.id).toBe(created.id);
    });
  });

  describe('stability', () => {
    it('keeps the ID across updateSession and refreshSession', async () => {
      const jar = createJar();
      const manager = new SessionManager(jar, config);
      const { id } = await manager.createSession(testUser);

      expect((await manager.updateSession({ meta: { theme: 'dark' } }))?.id).toBe(id);
      expect((await manager.refreshSession())?.id).toBe(id);
      expect((await readCookie(jar)).id).toBe(id);
    });

    it('ignores attempts to change the ID through updateSession', async () => {
      const jar = createJar();
      const manager = new SessionManager(jar, config);
      const { id } = await manager.createSession(testUser);

      const updated = await manager.updateSession({ id: 'attacker-chosen' } as any);

      expect(updated?.id).toBe(id);
      expect((await readCookie(jar)).id).toBe(id);
    });
  });

  describe('sealSession', () => {
    const data = { user: testUser, issuedAt: Date.now(), expiresAt: 0 };

    it('generates an ID when none is given', async () => {
      const sealed = await SessionManager.sealSession(data, config);

      expect((await unsealData<any>(sealed, { password: secret })).id).toMatch(UUID_V4);
    });

    it('keeps an ID that is given', async () => {
      const sealed = await SessionManager.sealSession({ ...data, id: 'fixed-test-id' }, config);

      expect((await unsealData<any>(sealed, { password: secret })).id).toBe('fixed-test-id');
    });
  });

  describe('sessions sealed before session IDs existed', () => {
    const issuedAt = 1700000000000;
    const sealLegacy = () =>
      sealData({ user: testUser, issuedAt, expiresAt: 0 }, { password: secret });

    it('derives a stable UUID v8 without rewriting the cookie', async () => {
      const jar = createJar({ [config.name]: await sealLegacy() });
      const before = jar.values.get(config.name);
      const manager = new SessionManager(jar, config);

      const first = await manager.getSession();
      const second = await manager.getSession();

      expect(first?.id).toMatch(UUID_V8);
      expect(second?.id).toBe(first?.id);
      expect(jar.values.get(config.name)).toBe(before);
    });

    it('derives the same ID for the same session in a separate request', async () => {
      const cookie = await sealLegacy();

      const a = await new SessionManager(createJar({ [config.name]: cookie }), config).getSession();
      const b = await new SessionManager(createJar({ [config.name]: cookie }), config).getSession();

      expect(a?.id).toMatch(UUID_V8);
      expect(b?.id).toBe(a?.id);
    });

    it('matches the ID the edge reader derives', async () => {
      const cookie = await sealLegacy();

      const node = await new SessionManager(createJar({ [config.name]: cookie }), config).getSession();
      const edge = await new EdgeSessionReader(secret, config.name).decryptSession(cookie);

      expect(edge?.id).toBe(node?.id);
    });

    it('persists the derived ID on refresh, even though issuedAt changes', async () => {
      const jar = createJar({ [config.name]: await sealLegacy() });
      const manager = new SessionManager(jar, config);
      const { id } = (await manager.getSession())!;

      const refreshed = await manager.refreshSession();
      const stored = await readCookie(jar);

      expect(id).toMatch(UUID_V8);
      expect(refreshed?.id).toBe(id);
      expect(stored.id).toBe(id);
      expect(stored.issuedAt).not.toBe(issuedAt);
      expect((await manager.getSession())?.id).toBe(id);
    });
  });

  describe('AuthUtils.deriveLegacySessionId', () => {
    it('is deterministic', async () => {
      expect(await AuthUtils.deriveLegacySessionId('u', 1, secret))
        .toBe(await AuthUtils.deriveLegacySessionId('u', 1, secret));
    });

    it('depends on the user, the issue time, and the secret', async () => {
      const base = await AuthUtils.deriveLegacySessionId('u', 1, secret);

      expect(await AuthUtils.deriveLegacySessionId('v', 1, secret)).not.toBe(base);
      expect(await AuthUtils.deriveLegacySessionId('u', 2, secret)).not.toBe(base);
      expect(await AuthUtils.deriveLegacySessionId('u', 1, 'another-secret-32-characters-long')).not.toBe(base);
    });
  });
});

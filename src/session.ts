import { getIronSession } from 'iron-session';
import { Session, SessionConfig, User, Logger } from './types';
import { AuthUtils } from './utils';
import { DefaultLogger } from './logger';

/**
 * Cookie store interface for framework agnostic cookie operations
 */
export interface CookieStore {
  get: (name: string) => { name: string; value: string } | undefined;
  set: (name: string, value: string, options?: CookieOptions) => void;
  delete?: (name: string) => void;
}

/**
 * Cookie options interface
 */
export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'lax' | 'strict' | 'none';
  path?: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
}

/**
 * Session manager class for handling authentication sessions
 */
export class SessionManager {
  private config: Required<SessionConfig>;
  private logger: Logger;

  constructor(
    private cookieStore: CookieStore,
    config: SessionConfig,
    logger?: Logger
  ) {
    this.config = {
      name: config.name,
      secret: config.secret,
      cookie: {
        httpOnly: true,
        secure: true,
        sameSite: 'lax' as const,
        path: '/',
        ...config.cookie,
      },
      cookieSizeThreshold: config.cookieSizeThreshold || 3500,
    };

    this.logger = logger || new DefaultLogger();

    // Validate secret length
    if (this.config.secret.length < 32) {
      throw new Error('Session secret must be at least 32 characters long');
    }
  }

  /**
   * Get session data from cookie
   */
  async getSession(): Promise<Session | null> {
    try {
      const sessionCookie = this.cookieStore.get(this.config.name);
      if (!sessionCookie) {
        return null;
      }

      // Create a temporary iron-session compatible store
      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as never,
        {
          cookieName: this.config.name,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      // Check if session is expired
      if (session.expiresAt && Date.now() > session.expiresAt) {
        this.logger.debug('Session expired', { expiresAt: session.expiresAt });
        await this.destroySession();
        return null;
      }

      return session;
    } catch (error) {
      this.logger.error('Failed to get session', { error: error instanceof Error ? error.message : 'Unknown error' });
      return null;
    }
  }  /**
   * Create a new session
   */
  async createSession(user: User, meta?: Record<string, unknown>): Promise<Session> {
    const now = Date.now();
    const sessionData: Session = {
      user,
      meta,
      issuedAt: now,
      expiresAt: 0, // Session expires when browser closes
    };

    try {
      const mainCookieName = this.config.name;
      const jsCookieName = `${this.config.name}-session`;

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as never,
        {
          cookieName: mainCookieName,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      // Set session data
      Object.assign(session, sessionData);
      await session.save();

      // Create JavaScript-accessible session boolean cookie
      this.cookieStore.set(jsCookieName, 'true', {
        httpOnly: false, // JavaScript accessible
        secure: this.config.cookie.secure,
        sameSite: this.config.cookie.sameSite,
        path: this.config.cookie.path,
        domain: this.config.cookie.domain,
        maxAge: this.config.cookie.maxAge,
      });

      // Check cookie size
      const cookieValue = this.cookieStore.get(mainCookieName)?.value || '';
      AuthUtils.checkCookieSize(cookieValue, this.config.cookieSizeThreshold, this.logger);

      this.logger.info('Session created', {
        userId: user.id,
        issuedAt: sessionData.issuedAt,
        mainCookie: mainCookieName,
        jsCookie: jsCookieName
      });

      return sessionData;
    } catch (error) {
      this.logger.error('Failed to create session', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId: user.id
      });
      throw error;
    }
  }

  /**
   * Update existing session
   */
  async updateSession(updates: Partial<Session>): Promise<Session | null> {
    try {
      const currentSession = await this.getSession();
      if (!currentSession) {
        return null;
      }

      const updatedSession: Session = {
        ...currentSession,
        ...updates,
      };

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as never,
        {
          cookieName: this.config.name,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      Object.assign(session, updatedSession);
      await session.save();

      // Check cookie size
      const cookieValue = this.cookieStore.get(this.config.name)?.value || '';
      AuthUtils.checkCookieSize(cookieValue, this.config.cookieSizeThreshold, this.logger);

      this.logger.debug('Session updated', {
        userId: updatedSession.user.id
      });

      return updatedSession;
    } catch (error) {
      this.logger.error('Failed to update session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }

  /**
   * Destroy the session
   */
  async destroySession(): Promise<void> {
    try {
      const mainCookieName = this.config.name;
      const jsCookieName = `${this.config.name}-session`;

      const ironStore = {
        get: this.cookieStore.get,
        set: this.cookieStore.set,
      };

      const session = await getIronSession<Session>(
        ironStore as never,
        {
          cookieName: mainCookieName,
          password: this.config.secret,
          cookieOptions: this.config.cookie,
        }
      );

      const userId = session.user?.id;
      session.destroy();

      // Also remove the JavaScript-accessible session boolean cookie
      if (this.cookieStore.delete) {
        this.cookieStore.delete(jsCookieName);
      }

      this.logger.info('Session destroyed', {
        userId,
        mainCookie: mainCookieName,
        jsCookie: jsCookieName
      });
    } catch (error) {
      this.logger.error('Failed to destroy session', {
        error: error instanceof Error ? error.message : 'Unknown error'
      });
      throw error;
    }
  }  /**
   * Check if session exists and is valid
   */
  async isAuthenticated(): Promise<boolean> {
    const session = await this.getSession();
    return session !== null && !!session.user;
  }

  /**
   * Get user from session
   */
  async getUser(): Promise<User | null> {
    const session = await this.getSession();
    return session?.user || null;
  }

  /**
   * Refresh session (sliding expiration)
   */
  async refreshSession(): Promise<Session | null> {
    const session = await this.getSession();
    if (!session) {
      return null;
    }

    // Update issued timestamp for sliding sessions
    return await this.updateSession({
      issuedAt: Date.now(),
    });
  }
}

/**
 * Create a cookie store adapter for Express.js
 */
export function createExpressCookieStore(req: unknown, res: unknown): CookieStore {
  const request = req as { cookies?: Record<string, string> };
  const response = res as { cookie: (name: string, value: string, options?: CookieOptions) => void; clearCookie: (name: string) => void };

  return {
    get: (name: string) => {
      const value = request.cookies?.[name];
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      response.cookie(name, value, options);
    },
    delete: (name: string) => {
      response.clearCookie(name);
    },
  };
}

/**
 * Create a cookie store adapter for Web API Request/Response
 */
export function createWebCookieStore(request: Request, response: Response): CookieStore {
  const cookies = new Map<string, string>();

  // Parse existing cookies from request
  const cookieHeader = request.headers.get('cookie');
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies.set(name, decodeURIComponent(value));
      }
    });
  }

  return {
    get: (name: string) => {
      const value = cookies.get(name);
      return value ? { name, value } : undefined;
    },
    set: (name: string, value: string, options?: CookieOptions) => {
      cookies.set(name, value);

      // Build cookie string
      let cookieString = `${name}=${encodeURIComponent(value)}`;

      if (options) {
        if (options.httpOnly) cookieString += '; HttpOnly';
        if (options.secure) cookieString += '; Secure';
        if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
        if (options.path) cookieString += `; Path=${options.path}`;
        if (options.domain) cookieString += `; Domain=${options.domain}`;
        if (options.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
        if (options.expires) cookieString += `; Expires=${options.expires.toUTCString()}`;
      }

      // Set cookie header on response
      const existingCookies = response.headers.get('set-cookie') || '';
      const newCookies = existingCookies ? `${existingCookies}, ${cookieString}` : cookieString;
      response.headers.set('set-cookie', newCookies);
    },
  };
}
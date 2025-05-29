/* eslint-disable @typescript-eslint/no-explicit-any */
import { getIronSession } from "iron-session";

export type Config = {
  name: string;
  secret: string;
  ttl?: number;
  setter: CookieStore | null;
  cookie: {
    httpOnly: boolean;
    secure: boolean;
    maxAge?: number;
    sameSite: "lax" | "strict" | "none";
    path?: string;
  };
}

/**
 * The high-level type definition of the .get() and .set() methods
 * of { cookies() } from "next/headers"
 */
interface CookieStore {
  get: (name: string) => {
    name: string;
    value: string;
  } | undefined;
  set: {
    (name: string, value: string, cookie?: Partial<any>): void;
    (options: any): void;
  };
}

export type AdaptAuthOptions = Partial<Config> & {
  setter: CookieStore | null;
}

/**
 * AdaptSession class provides methods for managing user sessions.
 * It is designed to work with Next.js and uses iron-session for session management.
 * This class allows creating, updating, checking, and destroying user sessions.
 * It also provides methods to check if a session is active.
 */
class AdaptSession {

  private config: Config = {
    name: 'adapt-auth-session',
    secret: 'your-secret-key',
    setter: null, // This should be `cookies()` from next/headers
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    },
  };

  constructor(options: Config) {
    this.config = { ...this.config, ...options };
  }

  /**
   * Creates a new session with the provided data.
   * This function initializes a new session and stores user data in it.
   * @param {Record<string, any>} data - The user data to be stored in the session.
   * @returns {Promise<any>} - Returns a promise that resolves to the created session.
   */
  public async createSession(data: Record<string, any>): Promise<any> {
    const session = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name,
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });

    // Set user data in the session
    session.data = data;
    session.active = true;

    // Save the session data cookie.
    await session.save();

    // Save the active session cookie.
    const activeSession = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name + '-session',
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });

    activeSession.active = true; // Mark the session as active
    await activeSession.save();

    return session;
  }

  /**
   * Checks if the user session is valid.
   * This function checks if the session cookie is valid and returns a boolean indicating the session status.
   * @returns {Promise<boolean>} - Returns a promise that resolves to true if the session is valid, false otherwise.
   */
  public async getSession(): Promise<boolean> {
    const session = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name,
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });

    return session;
  }

  /**
   * Updates the current session with new data.
   * This function allows updating user data in the existing session.
   * @param {Record<string, any>} data - The new user data to be updated in the session.
   * @returns {Promise<any>} - Returns a promise that resolves to the updated session data.
   */
  public async isActiveSession(): Promise<boolean> {
    const session = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name,
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });
    return session.active || false;
  }

  /**
   * Retrieves the current session.
   * This function fetches the current session data from the session store.
   * @returns {Promise<any>} - Returns a promise that resolves to the current session data.
   */
  public async updateSession(data: Record<string, any>): Promise<any> {
    const session = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name,
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });

    // Update user data in the session
    session.data = { ...session.data, ...data };

    // Save the session
    await session.save();
    return session;
  }

  /**
   * Destroys the current session.
   * This function removes the session cookie and clears the session data.
   * @returns {Promise<void>} - Returns a promise that resolves when the session is destroyed.
   */
  public async destroySession(): Promise<void> {
    const session = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name,
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });

    // Destroy the session
    await session.destroy();

    // Also destroy the active session cookie
    const activeSession = await getIronSession<any>(this.config.setter!, {
      cookieName: this.config.name + '-session',
      password: this.config.secret,
      cookieOptions: this.config.cookie,
    });
    await activeSession.destroy();

  }
}

export default AdaptSession;
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
 * Type for creating the session class.
 */
export type ConfigParams = Partial<Config> & {
  setter: CookieStore | null;
};

/**
 * Session data type.
 * This is the type of data that will be stored in the session.
 * It can be extended to include any user-specific data.
 */
export type SessionData = {
  active: boolean;
  data: Record<string, any>;
};


/**
 * The high-level type definition of the .get() and .set() methods
 * of { cookies() } from "next/headers"
 *
 * This is borrowed from the `iron-session` package because they don't export it.
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

/**
 * AdaptSession class provides methods for managing user sessions.
 * It is designed to work anywhere and uses iron-session for session management.
 * This class allows creating, updating, checking, and destroying user sessions.
 * It also provides methods to check if a session is active.
 */
class AdaptSession {

  private config: Config = {
    name: process.env.ADAPT_AUTH_SESSION_NAME || 'adapt-auth-session',
    secret: process.env.ADAPT_AUTH_SESSION_SECRET || 'your-secret-key',
    setter: null, // This should be `cookies()` from next/headers
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      path: '/',
    },
  };

  constructor(options: ConfigParams) {
    // Ensure that the setter is provided
    if (!options.setter) {
      throw new Error("Session setter (cookies) must be provided.");
    }
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
      cookieOptions: {
        httpOnly: false, // Active session cookie can be accessed by client-side code
        secure: true, // Ensure this is set to true in production
        sameSite: 'lax', // Adjust as necessary for your application
      },
    });

    activeSession.active = true; // Mark the session as active
    await activeSession.save();

    return session;
  }

  /**
   * Checks if the user session is valid.
   * This function checks if the session cookie is valid and returns a boolean indicating the session status.
   * @returns {Promise<SessionData>} - Returns a promise that resolves to true if the session is valid, false otherwise.
   */
  public async getSession(): Promise<SessionData | null> {
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
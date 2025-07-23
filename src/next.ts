/**
 * This is a convenience class to make it easier to work with the Next.js API.
 * It provides methods to handle common tasks.
 */

import SAML, { type LoginOptions} from './saml';
import Session from './session';
import { cookies } from 'next/headers';
import { type ReadonlyRequestCookies } from 'next/dist/server/web/spec-extension/adapters/request-cookies';

export type ConfigOptions = {
  cookieStore: ReadonlyRequestCookies;
};

export class AdaptNext {

  private session: Session;

  constructor({
    cookieStore,
  }: ConfigOptions) {
    this.session = new Session({ setter: cookieStore });
  }

  /**
   * The login method is used to initiate the SAML login process.
   * This method initiates the SAML login process.
   *
   * @throws {Error} If called in a browser environment.
   * @param {LoginOptions} options - Optional parameters for the login process.
   * @returns {Promise<void>} - Returns a promise that resolves when the login process is complete.
   * @example
   * const options = { destination: '/dashboard' };
   * await adaptNext.login(options);
   */
  public login = (options?: LoginOptions) => {
    // Check for a browser environment and throw an error if not in a server context
    if (typeof window !== 'undefined') {
      throw new Error("AdaptNext.login() should not be called in a browser environment.");
    }

    // If in a server context, initiate the SAML login process
    return SAML.login(options);
  }

  /**
   * The logout method is used to log out the user.
   * This method destroys the session and initiates the SAML logout process.
   * It should not be called in a browser environment.
   *
   * @throws {Error} If called in a browser environment.
   * @returns {Promise<void>} - Returns a promise that resolves when the logout process is complete.
   * @example
   * await adaptNext.logout();
   */
  public logout = async () => {
    // Check for a browser environment and throw an error if not in a server context
    if (typeof window !== 'undefined') {
      throw new Error("AdaptNext.logout() should not be called in a browser environment.");
    }
    return this.session.destroySession();
  }

  /**
   * The getSession method retrieves the current session data.
   * This method should not be called in a browser environment.
   *
   * @throws {Error} If called in a browser environment.
   * @returns {Promise<SessionData>} - Returns a promise that resolves to the session data.
   *
   * @example
   * const sessionData = await adaptNext.getSession();
   */
  public getSession = async () => {
    // Check for a browser environment and throw an error if not in a server context
    if (typeof window !== 'undefined') {
      throw new Error("AdaptNext.getSession() should not be called in a browser environment.");
    }

    // If in a server context, return the session data
    return this.session.getSession();
  }
}

/**
 * Create an instance of AdaptNext to use in your application.
 * This instance can be used to call methods like login.
 */
const cookieInstance: ReadonlyRequestCookies = await cookies();
const instance = new AdaptNext({ cookieStore: cookieInstance });
export default instance;

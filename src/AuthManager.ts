import axios, { AxiosResponse } from 'axios';
import { createHash, randomBytes } from 'crypto';
import {
  decode as jwtDecode,
  verify as jwtVerify,
} from 'jsonwebtoken'; // Ensure jsonwebtoken is correctly imported
import { AuthEventType, AuthManagerEvent, UserTokenPayload } from './types';

export class AuthManager {
  private static instance: AuthManager | null = null;

  private authServer: string;

  private realmName: string;

  private redirectUri: string;

  private onStateChange: (event: AuthManagerEvent) => void;

  private constructor(
    authServer: string,
    realmName: string,
    redirectUri: string,
    onStateChange: (event: AuthManagerEvent) => void,
  ) {
    this.authServer = authServer;
    this.realmName = realmName;
    this.redirectUri = redirectUri;
    this.onStateChange = onStateChange;
    AuthManager.instance = this;
  }

  public static initialize(
    authServer: string,
    realmName: string,
    redirectUri: string,
    onStateChange: (event: AuthManagerEvent) => void,
  ): AuthManager {
    if (!AuthManager.instance) {
      AuthManager.instance = new AuthManager(
        authServer,
        realmName,
        redirectUri,
        onStateChange,
      );
      AuthManager.instance
      .checkAccessToken(true)
      .then((token) => {
        onStateChange({
          type: AuthEventType.INITALIZED_IN,
          user: AuthManager.instance.tokenToPayload(token),
        });
      })
      .catch(() => {
        onStateChange({ type: AuthEventType.INITALIZED_OUT });
      });
    }
    return AuthManager.instance;
  }

  public static getInstance(): AuthManager {
    if (!AuthManager.instance) {
      throw new Error('AuthManager not initialized');
    }
    return AuthManager.instance;
  }

  private tokenToPayload(token: string): UserTokenPayload {
    return JSON.parse(atob(token.split('.')[1]));
  }

  private toBase64Url(base64String: string): string {
    return base64String
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private generatePKCEPair(): {
    verifier: string,
    challenge: string,
  } {
    const verifier =
      localStorage.getItem('codeVerifier') ??
      this.toBase64Url(randomBytes(32).toString('base64'));
    const challenge =
      localStorage.getItem('codeChallenge') ??
      this.toBase64Url(
        createHash('sha256').update(verifier).digest('base64'),
      );

    localStorage.setItem('codeVerifier', verifier);
    localStorage.setItem('codeChallenge', challenge);

    return { verifier, challenge };
  }

  public async refreshAccessToken(isInitilization: boolean = false): Promise<string> {
    try {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        throw new Error('No refresh token found');
      }

      const response = await axios.post(
        `${this.authServer}auth/refresh`,
        {
          refresh_token: refreshToken,
        },
      );
      this.saveTokens(response, true);
      return response.data.access_token;
    } catch (error) {
      console.error(`Refresh token error, logging out: ${error}`);
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      if (!isInitilization) {
        // throw refresh fail only if not initialization
        this.onStateChange({ type: AuthEventType.REFRESH_FAILED });
      }
      throw error;
    }
  }

  public async checkAccessToken(isInitilization: boolean = false): Promise<string> {
    const accessToken = localStorage.getItem('access_token');
    if (accessToken || this.isTokenExpired(accessToken)) {
      return this.refreshAccessToken(isInitilization);
    }
    return accessToken;
  }

  private isTokenExpired(token: string): boolean {
    const decoded = this.tokenToPayload(token);
    return decoded.exp < Date.now() / 1000;
  }

  public async mustBeLoggedIn(): Promise<void> {
    if (!(await this.isLoggedIn())) {
      this.onStateChange({
        type: AuthEventType.FAILED_MUST_LOGIN_CHECK,
      });
    }
  }

  public getLoginWithGoogleUri(): string {
    const { challenge } = this.generatePKCEPair();
    return `${this.authServer}auth/login_with_google?realm_name=${this.realmName}&redirect_uri=${encodeURIComponent(this.redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256`;
  }

  public async isLoggedIn(): Promise<boolean> {
    try {
      await this.checkAccessToken();
      return true;
    } catch (error) {
      return false;
    }
  }

  public async getAccessToken(mustBeLoggedIn: boolean = false): Promise<string> {
    try {
      return await this.checkAccessToken();
    } catch (error) {
      if (mustBeLoggedIn) {
        this.onStateChange({
          type: AuthEventType.FAILED_MUST_LOGIN_CHECK,
        });
      }
      return '';
    }
  }

  private saveTokens(response: AxiosResponse, byRefresh: boolean): void {
    localStorage.setItem('access_token', response.data.access_token);
    localStorage.setItem(
      'refresh_token',
      response.data.refresh_token,
    );
    this.onStateChange({
      type: byRefresh ? AuthEventType.USER_UPDATED : AuthEventType.USER_LOGGED_IN, 
      user: this.tokenToPayload(response.data.access_token),
     });
    const user = this.tokenToPayload(response.data.access_token);
    localStorage.setItem('user', JSON.stringify(user));
  }

  public async loginUsingPkce(code: string): Promise<void> {
    try {
      const codeVerifier = localStorage.getItem('codeVerifier');
      if (!codeVerifier) {
        throw new Error('Code verifier not found');
      }

      const response = await axios.post(
        `${this.authServer}auth/pkce_exchange`,
        {
          realm_name: this.realmName,
          code,
          redirect_uri: this.redirectUri,
          code_verifier: codeVerifier,
        },
      );
      this.saveTokens(response, false);
    } finally {
      localStorage.removeItem('codeVerifier');
      localStorage.removeItem('codeChallenge');
    }
  }

  public async logout(): Promise<void> {
    try {
      const accessToken = localStorage.getItem('access_token');
      if (!accessToken) {
        throw new Error('Access token not found');
      }
      await axios.post(
        `${this.authServer}auth/logout`,
        {},
        {
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      this.onStateChange({ type: AuthEventType.USER_LOGGED_OUT });
    }
  }

  public static async validateToken(
    authServer: string,
    bearerToken: string,
  ): Promise<boolean> {
    // @todo tests missing for this static validation
    try {
      const decodedToken = jwtDecode(bearerToken, {
        complete: true,
      })?.payload;

      if (!decodedToken) {
        return false;
      }

      const { data: publicKey } = await axios.get(
        `${authServer}public/public_key`,
      );
      const { data: algo } = await axios.get(
        `${authServer}public/algo`,
      );

      jwtVerify(bearerToken, publicKey, { algorithms: [algo] });

      const { data: revokedIds } = await axios.get(
        `${authServer}public/revoked_ids`,
      );
      // eslint-disable-next-line @typescript-eslint/dot-notation
      return !revokedIds.includes(decodedToken['id']);
    } catch (error) {
      return false;
    }
  }

  public static resetInstance(): void {
    AuthManager.instance = null;
  }
}

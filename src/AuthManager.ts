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

  public async refreshAccessToken(isInitialization: boolean = false): Promise<string> {
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
      if (!isInitialization) {
        // throw refresh fail only if not initialization
        this.onStateChange({ type: AuthEventType.REFRESH_FAILED });
      }
      throw error;
    }
  }

  public async checkAccessToken(isInitilization: boolean = false): Promise<string> {
    const accessToken = localStorage.getItem('access_token');
    if (accessToken && this.isTokenExpired(accessToken)) {
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


  public async platformCheck(email: string, token: string): Promise<boolean> {
    const response = await axios.post(
        `${this.authServer}auth/email/platform_check`,
        {
          realm_name: this.realmName,
          email,
        },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return (response.status === 200) ? response.data : {'platforms': []};
  }

  public async verifyEmail(email: string, token: string): Promise<boolean> {
    const response = await axios.post(
      `${this.authServer}auth/email/verify`,
      {
        realm_name: this.realmName,
        email,
        token,
      },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return response.status === 200;
  }

  public async doPassReset(email: string, token: string, newPassword: string): Promise<boolean> {
    const response = await axios.post(
        `${this.authServer}auth/email/do_pass_reset`,
        {
          realm_name: this.realmName,
          email,
          token,
          new_password: newPassword,
        },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return response.status === 200;
  }

  public async changeEmail(email: string): Promise<boolean> {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
      throw new Error('Access token not found');
    }
    const response = await axios.post(
      `${this.authServer}auth/email/change_email`,
      {
        realm_name: this.realmName,
        email,
      },
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return response.status === 200;
  }

  public async initPasswordReset(email: string): Promise<boolean> {
    const response = await axios.post(
      `${this.authServer}auth/email/init_pass_reset`,
      {
        realm_name: this.realmName,
        email,
      },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return response.status === 200 || response.status === 201;
  }

  public async changePassword(oldPassword: string, newPassword: string, email: string): Promise<boolean> {
    const accessToken = localStorage.getItem('access_token');
    if (!accessToken) {
      throw new Error('Access token not found');
    }
    const response = await axios.post(
      `${this.authServer}auth/email/change_pass`,
      {
        realm_name: this.realmName,
        email,
        old_password: oldPassword,
        new_password: newPassword,
      },
      {
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    );
    if (response.data.error || response.data.errors) {
      throw new Error(response.data.error || response.data.message);
    }

    return response.status === 200;
  }

  public async registerUsingEmail(
      firstName: string,
      lastName: string,
      email: string,
      password: string
  ): Promise<void> {
    const response = await axios.post(
      `${this.authServer}auth/email/register`,
      {
        realm_name: this.realmName,
        first_name: firstName,
        last_name: lastName,
        email,
        password,
      },
    );
    if (response.data.message || response.data.error) {
      throw new Error(response.data.message || response.data.error);
    }

    if (!response.data.access_token) {
        throw new Error('Something went wrong');
    }

    this.saveTokens(response, false);
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

  public async loginUsingEmail(email: string, password: string): Promise<void> {
    const response = await axios.post(
      `${this.authServer}auth/email/login`,
      {
        realm_name: this.realmName,
        email,
        password,
      },
    );
    if (response.data.message || response.data.error) {
      throw new Error(response.data.message || response.data.error);
    }
    this.saveTokens(response, false);
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
  ): Promise<UserTokenPayload> {
    // @todo tests missing for this static validation
    // @todo add caching for public key and algo
    const decodedToken = jwtDecode(bearerToken, {
      complete: true,
    })?.payload as unknown as UserTokenPayload;

    if (!decodedToken) {
      throw new Error('Not a valid jwt token');
    }

    const userToken: UserTokenPayload = {
        id: decodedToken.id,
        iss: decodedToken.iss,
        sub: typeof decodedToken.sub === 'string' ? parseInt(decodedToken.sub) : decodedToken.sub,
        first_name: decodedToken.first_name,
        last_name: decodedToken.last_name,
        email: decodedToken.email,
        aud: decodedToken.aud,
        iat: decodedToken.iat,
        exp: decodedToken.exp,
        scopes: decodedToken.scopes,
        realm: decodedToken.realm,
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
    if(revokedIds.includes(decodedToken.id)){
      throw new Error('Token is revoked');
    }
    return userToken;
  }

  public static resetInstance(): void {
    AuthManager.instance = null;
  }
}

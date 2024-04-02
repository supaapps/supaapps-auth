import axios from 'axios';
import { createHash, randomBytes } from 'crypto';

export class AuthManager {
    private static instance: AuthManager | null = null;
    private readonly authServer: string | null = null;

    private readonly realmName: string | null = null;

    private readonly redirectUri: string | null = null;
    private readonly loginCallback: () => void = () => {};

    public constructor(authServer: string, realmName: string, redirectUri: string, loginCallback: () => void) {
        this.authServer = authServer;
        this.realmName = realmName;
        this.redirectUri = redirectUri;
        this.loginCallback = loginCallback;
        AuthManager.instance = this;
    }

    public static getInstance<T>(): AuthManager{
        if (!AuthManager.instance) {
            throw new Error('AuthManager not initialized');
        }
        return AuthManager.instance;
    }

    private  toBase64Url = (base64String: string) => {
        return base64String
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
    };
    private  generatePKCEPair = () => {
        const NUM_OF_BYTES = 32; // This will generate a verifier of sufficient length
        const HASH_ALG = 'sha256';

        // Generate code verifier
        const newCodeVerifier = this.toBase64Url(
          randomBytes(NUM_OF_BYTES).toString('base64'),
        );

        // Generate code challenge
        const hash = createHash(HASH_ALG)
          .update(newCodeVerifier)
          .digest('base64');
        const newCodeChallenge = this.toBase64Url(hash);

        return { newCodeVerifier, newCodeChallenge };
    };

    private async refreshAccessToken(): Promise<string> {
        return new Promise(async (resolve, reject) => {
            try {
                const refreshToken: string | null = localStorage.getItem('refresh_token');
                if (!refreshToken) {
                    throw new Error('No refresh token found');
                }
                const decodedRefreshToken = JSON.parse(atob(refreshToken.split('.')[1]));
                if (decodedRefreshToken) {
                    const currentTime = Date.now() / 1000;
                    if (decodedRefreshToken.exp < currentTime) {
                        throw new Error('Refresh token expired');
                    }
                }
                await fetch(`${this.authServer}auth/refresh`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        refresh_token: refreshToken,
                    }),
                })
                    .then((response) => {
                        if (response.status !== 200) {
                            throw new Error('Failed to refresh the token');
                        }
                        return response.json();
                    })
                    .then((exchangeJson) => {
                        localStorage.setItem('refresh_token', exchangeJson.refresh_token);
                        localStorage.setItem('access_token', exchangeJson.access_token);
                        resolve(exchangeJson.access_token);
                    })
                    .catch((error) => {
                        reject(error);
                    });
            } catch (error) {
                reject(error);
            }
        });
    }

    private async checkAccessToken(): Promise<string> {
        return new Promise(async (resolve, reject) => {
            try {
                let accessToken: string | null = localStorage.getItem('access_token');

                if (!accessToken) {
                    accessToken = await this.refreshAccessToken();
                } else {
                    const decodedToken = accessToken ? JSON.parse(atob(accessToken.split('.')[1])) : null;
                    const currentTime = Date.now() / 1000;

                    if (decodedToken && decodedToken.exp < currentTime) {
                        accessToken = await this.refreshAccessToken();
                    }
                }

                resolve(accessToken);
            } catch (error) {
                reject(error);
            }
        });
    }

    public async mustBeLoggedIn(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            this.isLoggedIn().then((isLoggedIn) => {
                if (!isLoggedIn) {
                    this.loginCallback();
                    return resolve(false);
                }
                return resolve(true);
            });
        });
    }

    public getLoginWithGoogleUri(): string {
        // get or create codeVerifier and codeChallenge from localstorage
        const { newCodeVerifier, newCodeChallenge } = this.generatePKCEPair();
        let codeVerifier = localStorage.getItem('codeVerifier') || newCodeVerifier;
        let codeChallenge = localStorage.getItem('codeChallenge') || newCodeChallenge;
        localStorage.setItem('codeVerifier', codeVerifier);
        localStorage.setItem('codeChallenge', codeChallenge);

        if (this.authServer && this.realmName && this.redirectUri) {
            return  `${this.authServer}auth/login_with_google?realm_name=${this.realmName}` +
              `&redirect_uri=${encodeURIComponent(this.redirectUri)}&code_challenge=${codeChallenge}&code_challenge_method=S256`
        }
    }

    public async isLoggedIn(): Promise<boolean> {
        // todo here: check if refresh token is expired and if so, try to refresh, then update token
        return new Promise(async (resolve, reject) => {
            try {
                await this.checkAccessToken();
                return resolve(true);
            } catch (error) {
                reject(error);
            }
        });
    }

    public async getAccessToken(): Promise<string> {
        // todo here: check if refresh token is expired and if so, try to refresh, then update token
        // otherwise throw error
        return new Promise(async (resolve, reject) => {
            try {
                const accessToken = await this.checkAccessToken();

                return resolve(accessToken);
            } catch (error) {
                reject(error);
            }
        });
    }

    public async loginUsingPkce(code): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                const codeVerifier = localStorage.getItem('codeVerifier');
                if (codeVerifier) {
                    fetch(`${this.authServer}auth/pkce_exchange`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            realm_name: this.realmName,
                            code: code,
                            redirect_uri: this.redirectUri,
                            code_verifier: codeVerifier,
                        }),
                    })
                      .then((response) => {
                          localStorage.removeItem('codeVerifier');
                          localStorage.removeItem('codeChallenge');
                          if (response.status !== 200) {
                              throw new Error('Failed to exchange code for token');
                          }
                          return response.json();
                      })
                      .then((exchangeJson) => {
                          localStorage.setItem('access_token', exchangeJson.access_token);
                          localStorage.setItem('refresh_token', exchangeJson.refresh_token);
                          resolve();
                      })
                      .catch((error) => {
                          localStorage.removeItem('codeVerifier');
                          localStorage.removeItem('codeChallenge');
                          reject(error);
                      });
                }
            } catch (error) {
                reject(error);
            }
        });
    }

    public async logout(): Promise<void> {
        return new Promise((resolve, reject) => {
            try {
                const bearerToken = localStorage.getItem('access_token');
                localStorage.removeItem('access_token');
                localStorage.removeItem('refresh_token');
                fetch(`${this.authServer}auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${bearerToken}`,
                    },
                }).then((response) => {
                    if (response.status !== 200) {
                        throw new Error('Failed to attempt logout')
                    }
                    resolve();
                }).catch((error) => {
                    reject(error);
                })
            } catch (error) {
                reject(error);
            }
        })
    }

    public static async validateToken(authServer: string, bearerToken: string): Promise<boolean> {
        return new Promise<boolean>(async (resolve, reject) => {
            try {
                const accessToken = bearerToken.includes('Bearer ') ? bearerToken.replace('Bearer ', '') : bearerToken;
                const decodedToken = accessToken ? JSON.parse(atob(accessToken.split('.')[1])) : null;

                if (!decodedToken) {
                    return resolve(false);
                }

                const currentTime = Date.now() / 1000;
                if (decodedToken.exp < currentTime) {
                    return resolve(false);
                }

                const { data: publicKey } = await axios.get(`${authServer}public/public_key`);
                const { data: algo } = await axios.get(`${authServer}public/algo`);
                const jwt = require('jsonwebtoken');
                jwt.verify(accessToken, publicKey, { algorithms: [algo] }, (error, payload) => {
                    if (error) {
                        return resolve(false);
                    }
                    axios.get(`${authServer}public/revoked_ids`).then(({ data: revokedIds }) => {
                        if (revokedIds && (revokedIds as number[]).includes(decodedToken['id'])) {
                            return resolve(false);
                        }
                        return resolve(true);
                    });
                });
            } catch (error) {
                reject(error);
            }
        })
    }
}

import axios from 'axios';
import { createHash, randomBytes } from 'crypto';


export class AuthManager {
    private static instance: AuthManager | null = null;
    private readonly authServer: string | null = null;

    private readonly realmName: string | null = null;

    private readonly redirectUri: string | null = null;
    public constructor(authServer: string, realmName: string, redirectUri: string) {
        this.authServer = authServer;
        this.realmName = realmName;
        this.redirectUri = redirectUri;
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
        const codeVerifier = this.toBase64Url(
            randomBytes(NUM_OF_BYTES).toString('base64'),
        );

        // Generate code challenge
        const hash = createHash(HASH_ALG)
            .update(codeVerifier)
            .digest('base64');
        const codeChallenge = this.toBase64Url(hash);

        return { codeVerifier, codeChallenge };
    };
    public getLoginWithGoogleUri(): string {
        const { codeVerifier, codeChallenge } = this.generatePKCEPair();
        localStorage.setItem('codeVerifier', codeVerifier);
        localStorage.setItem('codeChallenge', codeChallenge);

        if (this.authServer && this.realmName && this.redirectUri) {
            return  `${this.authServer}auth/login_with_google?realm_name=${this.realmName}` +
                `&redirect_uri=${encodeURIComponent(this.redirectUri)}&code_challenge=${codeChallenge}&code_challenge_method=S256`
        }
    }
    public async isLoggedIn(): Promise<boolean> {
        // todo here: check if refresh token is expired and if so, try to refresh, then update token
        return new Promise((resolve, reject) => {
            try {
                const accessToken: string | null = localStorage.getItem('access_token');
                if (!accessToken) {
                    return resolve(false);
                }
                // decode access token and check if it's expired
                const decodedToken = accessToken ? JSON.parse(atob(accessToken.split('.')[1])) : null;
                if (decodedToken) {
                    const currentTime = Date.now() / 1000;
                    if (decodedToken.exp < currentTime) {
                        // add refresh check here instead and
                        localStorage.removeItem('access_token');
                        return resolve(false);
                    }
                }

                return resolve(true);
            } catch (error) {
                reject(error);
            }
        });
    }

    public async getAccessToken(): Promise<string> {
        // todo here: check if refresh token is expired and if so, try to refresh, then update token
        // otherwise throw error
        return new Promise((resolve, reject) => {
            try {
                const accessToken: string | null = localStorage.getItem('access_token');
                if (!accessToken) {
                    throw new Error('No access token found');
                }
                // decode access token and check if it's expired
                const decodedToken = accessToken ? JSON.parse(atob(accessToken.split('.')[1])) : null;
                if (decodedToken) {
                    const currentTime = Date.now() / 1000;
                    if (decodedToken.exp < currentTime) {
                        // add refresh check here instead and
                        localStorage.removeItem('access_token');
                        throw new Error('Access token expired');
                    }
                }

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
                            reject(error);
                        });
                }
            } catch (error) {
                reject(error);
            }
        });
    }

}

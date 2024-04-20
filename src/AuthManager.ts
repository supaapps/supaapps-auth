import axios, { AxiosResponse } from 'axios';
import { createHash, randomBytes } from 'crypto';
import {decode as jwtDecode, verify as jwtVerify} from 'jsonwebtoken';  // Ensure jsonwebtoken is correctly imported

export class AuthManager {
    private static instance: AuthManager | null = null;
    private authServer: string;
    private realmName: string;
    private redirectUri: string;
    private loginCallback: () => void;

    private constructor(authServer: string, realmName: string, redirectUri: string, loginCallback: () => void) {
        this.authServer = authServer;
        this.realmName = realmName;
        this.redirectUri = redirectUri;
        this.loginCallback = loginCallback;
        AuthManager.instance = this;
    }

    public static initialize(authServer: string, realmName: string, redirectUri: string, loginCallback: () => void): AuthManager {
        if (!AuthManager.instance) {
            AuthManager.instance = new AuthManager(authServer, realmName, redirectUri, loginCallback);
        }
        return AuthManager.instance;
    }

    public static getInstance(): AuthManager {
        if (!AuthManager.instance) {
            throw new Error('AuthManager not initialized');
        }
        return AuthManager.instance;
    }

    private toBase64Url(base64String: string): string {
        return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    private generatePKCEPair(): { verifier: string; challenge: string } {
        const verifier = localStorage.getItem('codeVerifier') ?? this.toBase64Url(randomBytes(32).toString('base64'));
        const challenge = localStorage.getItem('codeChallenge') ?? this.toBase64Url(createHash('sha256').update(verifier).digest('base64'));

        localStorage.setItem('codeVerifier', verifier);
        localStorage.setItem('codeChallenge', challenge);

        return { verifier, challenge };
    }

    public async refreshAccessToken(): Promise<string> {
        try {
            const refreshToken = localStorage.getItem('refresh_token');
            if (!refreshToken) {
                throw new Error('No refresh token found');
            }

            const response = await axios.post(`${this.authServer}auth/refresh`, {
                refresh_token: refreshToken
            });

            localStorage.setItem('refresh_token', response.data.refresh_token);
            localStorage.setItem('access_token', response.data.access_token);
            const user = jwtDecode(response.data.access_token);
            localStorage.setItem('user', JSON.stringify(user));
            return response.data.access_token;
        } catch (error) {
            console.error(`Refresh token error, logging out: ${error}`);
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            this.loginCallback();
            throw error;
        }
    }

    public async checkAccessToken(): Promise<string> {
        let accessToken = localStorage.getItem('access_token');
        if (!accessToken || this.isTokenExpired(accessToken)) {
            return this.refreshAccessToken();
        }
        return accessToken;
    }

    private isTokenExpired(token: string): boolean {
        const decoded = JSON.parse(atob(token.split('.')[1]));
        return decoded.exp < Date.now() / 1000;
    }

    public async mustBeLoggedIn(): Promise<boolean> {
        return this.isLoggedIn() || (this.loginCallback(), false);
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

    public async getAccessToken(): Promise<string> {
        return this.checkAccessToken();
    }

    private saveTokens(response: AxiosResponse): void {
        localStorage.setItem('access_token', response.data.access_token);
        localStorage.setItem('refresh_token', response.data.refresh_token);
        const user = jwtDecode(response.data.access_token);
        localStorage.setItem('user', JSON.stringify(user));
    }

    public async loginUsingPkce(code: string): Promise<void> {
        try {
            const codeVerifier = localStorage.getItem('codeVerifier');
            if (!codeVerifier) {
                throw new Error('Code verifier not found');
            }

            const response = await axios.post(`${this.authServer}auth/pkce_exchange`, {
                realm_name: this.realmName,
                code,
                redirect_uri: this.redirectUri,
                code_verifier: codeVerifier,
            });
            this.saveTokens(response);
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
            await axios.post(`${this.authServer}auth/logout`, {}, {
                headers: { Authorization: `Bearer ${accessToken}` }
            });
        } finally {
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
        }
    }

    public static async validateToken(authServer: string, bearerToken: string): Promise<boolean> {
        // @todo tests missing for this static validation
        try {
            const decodedToken = jwtDecode(bearerToken, { complete: true })?.payload;

            if (!decodedToken) {
                return false;
            }

            const { data: publicKey } = await axios.get(`${authServer}public/public_key`);
            const { data: algo } = await axios.get(`${authServer}public/algo`);

            jwtVerify(bearerToken, publicKey, { algorithms: [algo] });

            const { data: revokedIds } = await axios.get(`${authServer}public/revoked_ids`);
            return !revokedIds.includes(decodedToken['id']);
        } catch (error) {
            return false;
        }
    }

    public static resetInstance(): void {
        AuthManager.instance = null;
    }
}

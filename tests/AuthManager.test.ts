import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { AuthManager } from '../src/AuthManager';
import { basename } from 'path';

const mock = new MockAdapter(axios);


describe('AuthManager Tests', () => {

    beforeEach(() => {
        localStorage.clear();  // Clear localStorage before each test
        AuthManager.resetInstance();  // Reset singleton instance
      });
 


    it('singleton: should throw when getting instance without initialization', () => {
        expect(() => AuthManager.getInstance()).toThrow('AuthManager not initialized');
    });

    it('singleton: should create an instance', () => {
      const loginCallback = jest.fn();
      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
      expect(AuthManager.getInstance()).toBeInstanceOf(AuthManager);
    });
  
    it('PKCE Generation: generates a PKCE pair and stores in local storage', () => {
      const loginCallback = jest.fn();
      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
        // Accessing the private method by casting to any
        const pkce = (manager as any).generatePKCEPair();

        expect(pkce).toHaveProperty('verifier');
        expect(pkce).toHaveProperty('challenge');
        expect(pkce.verifier).toMatch(/[\w-_]+/);
        expect(pkce.challenge).toMatch(/[\w-_]+/);
  
      expect(pkce.verifier).toMatch(/[\w-_=]+/);
      expect(pkce.challenge).toMatch(/[\w-_=]+/);
      expect(localStorage.setItem).toHaveBeenCalledWith('codeVerifier', expect.anything());
      expect(localStorage.setItem).toHaveBeenCalledWith('codeChallenge', expect.anything());
    });
  

    it('refreshes access token when expired', async () => {
      mock.onPost('http://auth-server.com/auth/refresh').reply(200, {
        access_token: 'newAccessToken',
        refresh_token: 'newRefreshToken'
      });
  
      const loginCallback = jest.fn();
      // check that we set localstorage correct
      localStorage.setItem('access_token', 'mockAccessToken');
      localStorage.setItem('refresh_token', 'mockRefreshToken');

      const refresh = localStorage.getItem('refresh_token');
        expect(refresh).toEqual('mockRefreshToken');

      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
      const token = await manager.refreshAccessToken();
  
      expect(token).toEqual('newAccessToken');
      expect(localStorage.setItem).toHaveBeenCalledWith('access_token', 'newAccessToken');
      expect(localStorage.setItem).toHaveBeenCalledWith('refresh_token', 'newRefreshToken');
    });
  

    it('throws an error when no refresh token is found', async () => {
      localStorage.removeItem('refresh_token');

      const loginCallback = jest.fn();
      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
      
      await expect(manager.refreshAccessToken()).rejects.toThrow('No refresh token found');
      await expect(loginCallback).toHaveBeenCalled();
    });

    it('logs in using PKCE and updates local storage', async () => {
      localStorage.setItem('codeVerifier', 'mockCodeVerifier');
      /*
            {
            "sub": "1234567890",
            "name": "John Doe",
            "iat": 1516239022
            }
        */
      const accessToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';


      mock.onPost('http://auth-server.com/auth/pkce_exchange').reply(200, {
        access_token: accessToken,
        refresh_token: 'validRefreshToken'
      });
  
      const loginCallback = jest.fn();
      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
      await manager.loginUsingPkce('mockCode');
  
      expect(localStorage.setItem).toHaveBeenCalledWith('access_token', accessToken);
      expect(localStorage.setItem).toHaveBeenCalledWith('refresh_token', 'validRefreshToken');
      const userSub = JSON.parse(localStorage.getItem('user') ?? '').sub;
      expect(userSub).toEqual('1234567890');
    });
  
    it('logs out and clears local storage', async () => {
      localStorage.setItem('access_token', 'validAccessToken');
      mock.onPost('http://auth-server.com/auth/logout').reply(200);
  
      const loginCallback = jest.fn();
      const manager = AuthManager.initialize('http://auth-server.com/', 'example-realm', 'http://myapp.com/callback', loginCallback);
      await manager.logout();
  
      expect(localStorage.removeItem).toHaveBeenCalledWith('access_token');
      expect(localStorage.removeItem).toHaveBeenCalledWith('refresh_token');
    });

  
  
});
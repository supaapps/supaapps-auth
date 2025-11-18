import axios from 'axios';
import MockAdapter from 'axios-mock-adapter';
import { AuthManager } from '../src/AuthManager';
import { AuthEventType } from '../src/types';
import { beforeEach, describe, expect, it, Mock, vi } from 'vitest';

const mock = new MockAdapter(axios);

const tokenThatWontExpire1 =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZmlyc3RfbmFtZSI6IkpvaG4gRG9lIiwibGFzdF9uYW1lIjoiRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzY29wZXMiOiIvcm9vdC8qIiwiZXhwIjo5OTk5OTk5OTk5LCJpZCI6MiwiaXNzIjoxMjMsImF1ZCI6InRlc3RpbmcifQ.843X4Zq2WgNSu8fjRKx-kd_FbDqY_eVkgu2wZZbhhwE';
const tokenThatWontExpire2 =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZmlyc3RfbmFtZSI6IkpvaG4gRG9lIiwibGFzdF9uYW1lIjoiRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzY29wZXMiOiIvcm9vdC8qIiwiZXhwIjo5OTk5OTk5OTk5LCJpZCI6MiwiaXNzIjoxMjMsImF1ZCI6InRlc3RpbmcifQ.843X4Zq2WgNSu8fjRKx-kd_FbDqY_eVkgu2wZZbhhwE';
const tokenThatExpired =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZmlyc3RfbmFtZSI6IkpvaG4gRG9lIiwibGFzdF9uYW1lIjoiRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJzY29wZXMiOiIvcm9vdC8qIiwiZXhwIjo1MDAsImlkIjoyLCJpc3MiOjEyMywiYXVkIjoidGVzdGluZyJ9.ungpbhHfCM5ZP5oiZ1RnMkJ-NKJI8s3_IPJptjyKHR4';

describe('AuthManager Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(Storage.prototype, 'getItem');
    vi.spyOn(Storage.prototype, "setItem");
    vi.spyOn(Storage.prototype, "removeItem");

    AuthManager.resetInstance();
  });

  it('singleton: should throw when getting instance without initialization', () => {
    expect(() => AuthManager.getInstance()).toThrow(
      'AuthManager not initialized',
    );
  });

  it('singleton: should create an instance', () => {
    const loginCallback = vi.fn();
    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );
    expect(AuthManager.getInstance()).toBeInstanceOf(AuthManager);
  });

  it('PKCE Generation: generates a PKCE pair and stores in local storage', () => {
    const loginCallback = vi.fn();
    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );
    // Accessing the private method by casting to any
    const pkce = (manager as any).generatePKCEPair();

    expect(pkce).toHaveProperty('verifier');
    expect(pkce).toHaveProperty('challenge');
    expect(pkce.verifier).toMatch(/[\w-_]+/);
    expect(pkce.challenge).toMatch(/[\w-_]+/);

    expect(pkce.verifier).toMatch(/[\w-_=]+/);
    expect(pkce.challenge).toMatch(/[\w-_=]+/);
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'codeVerifier',
      expect.anything(),
    );
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'codeChallenge',
      expect.anything(),
    );
  });

  it('refreshes access token when expired', async () => {
    mock.onPost('http://auth-server.com/auth/refresh').reply(200, {
      access_token: tokenThatWontExpire2,
      refresh_token: 'newRefreshToken',
    });

    const loginCallback = vi.fn()
    // check that we set localstorage correct
    localStorage.setItem('access_token', tokenThatExpired);
    localStorage.setItem('refresh_token', 'mockRefreshToken');

    const refresh = localStorage.getItem('refresh_token');
    expect(refresh).toEqual('mockRefreshToken');

    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );
    const token = await manager.refreshAccessToken();

    expect(token).toEqual(tokenThatWontExpire2);
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'access_token',
      tokenThatWontExpire2,
    );
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'refresh_token',
      'newRefreshToken',
    );
  });

  describe('AuthManager Tests isolated ', () => {
    it("doesn't refresh access token when its not expired", async () => {
      const stateChange = vi.fn()

      // check that we set localstorage correct
      localStorage.setItem('access_token', tokenThatWontExpire1);
      localStorage.setItem('refresh_token', 'mockRefreshToken');

      const manager = AuthManager.initialize(
        'http://auth-server.com/',
        'example-realm',
        'http://myapp.com/callback',
        stateChange,
      );

      const currentCallCount = (localStorage.getItem as Mock)
        .mock?.calls?.length;

      await manager.getAccessToken();

      expect(localStorage.getItem).toHaveBeenCalledTimes(
        currentCallCount + 1,
      );
    });
  });

  it('throws an error when no refresh token is found', async () => {
    localStorage.removeItem('refresh_token');

    const loginCallback = vi.fn()
    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );

    await expect(manager.refreshAccessToken()).rejects.toThrow(
      'No refresh token found',
    );
    await expect(loginCallback).toHaveBeenCalledWith({
      type: AuthEventType.REFRESH_FAILED,
    });
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
    const accessToken =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

    mock
      .onPost('http://auth-server.com/auth/pkce_exchange')
      .reply(200, {
        access_token: accessToken,
        refresh_token: 'validRefreshToken',
      });

    const loginCallback = vi.fn()
    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );
    await manager.loginUsingPkce('mockCode');

    expect(localStorage.setItem).toHaveBeenCalledWith(
      'access_token',
      accessToken,
    );
    expect(localStorage.setItem).toHaveBeenCalledWith(
      'refresh_token',
      'validRefreshToken',
    );
    const userSub = JSON.parse(
      localStorage.getItem('user') ?? '',
    ).sub;
    expect(userSub).toEqual('1234567890');
  });

  it('logs out and clears local storage', async () => {
    mock.onPost('http://auth-server.com/auth/logout').reply(200);

    const loginCallback = vi.fn()
    const manager = AuthManager.initialize(
      'http://auth-server.com/',
      'example-realm',
      'http://myapp.com/callback',
      loginCallback,
    );
    localStorage.setItem('access_token', tokenThatWontExpire1);
    await manager.logout();

    expect(localStorage.removeItem).toHaveBeenCalledWith(
      'access_token',
    );
    expect(localStorage.removeItem).toHaveBeenCalledWith(
      'refresh_token',
    );
  });
});

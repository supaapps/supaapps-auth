
export enum AuthEventType {
    INITALIZED_IN = 'initialized-logged-in',
    INITALIZED_OUT = 'initialized-logged-out',
    USER_LOGGED_IN = 'user-logged-in',
    USER_LOGGED_OUT = 'user-logged-out',
    USER_UPDATED = 'user-updated',
    FAILED_MUST_LOGIN_CHECK = 'failed-must-login',
    REFRESH_FAILED = 'refresh-failed',
}

export interface UserTokenPayload {
    id: number;
    iss: string;
    sub: number | string;
    first_name: string;
    last_name: string;
    email: string;
    aud: string;
    iat: number;
    exp: number;
    scopes: string;
    realm: string;
}

export interface AuthManagerEvent {
    type:  AuthEventType;
    user?: UserTokenPayload;
}

# TODO


`npm i supaapps-auth`


- Initialize
```ts
        new AuthManager(
            'https://supaapps-auth-api.testing.sacl.io/',
            'root',
            'http://localhost:3001/exchange',
            () => {
                // redirect to login
            }
        );
```


- Require login

```ts
import {AuthManager} from "./AuthManager";

const authManager = AuthManager.getInstance();
authManager.mustBeLoggedIn().then((isLoggedIn) => {
    if (isLoggedIn) {
        // do something
    }
});

// or 

AuthManager.getInstance().mustBeLoggedIn();
```


- Get user info

```ts
authManager.mustBeLoggedIn().then(
            (isLoggedIn) => {
                isLoggedIn && authManager.getAccessToken().then(
                    (token) => {
                        const decodedToken = JSON.parse(atob(token.split('.')[1]));
                        // access info for example 
                        // decodedToken.first_name
                    }
                );
            }
        )
```



Get login uri

```ts
AuthManager.getInstance().getLoginWithGoogleUri()
```


- Log user out

```ts
await authManager.logout();
// or
authManager.logout().then(() => {
  // user is now logged out
})
```

- Validate access token

```typescript
import { AuthManager } from './AuthManager';

const isValid = await AuthManager.validateToken(BEARER_HEADER_OR_ACCESS_TOKEN)
// or
AuthManager.validateToken(BEARER_OR_ACCESS_TOKEN).then((isValid) => {
  if (isValid) {
    // token is valid
  }
})
```
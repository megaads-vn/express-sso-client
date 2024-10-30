# express-sso-client

`express-sso-client` is an Express middleware library for handling Single Sign-On (SSO) authentication with JWT token support for MegaAds.Vn. This library includes middleware to protect routes and an SSO callback handler that verifies tokens with an external server and sets them in secure cookies.

## Features
- Middleware for protecting routes with SSO authentication.
- SSO callback handler that verifies tokens with an external verification server.
- JWT token support with forced expiration.
- Secure token storage in cookies.
- Support Typescripts

## Installation

Install `express-sso-client` and required dependencies:

```bash
npm install @megaads/express-sso-client
```

## Usage
Use ssoMiddleware to protect routes. If a user is not authenticated, they are redirected to the SSO login page.

```
const express = require('express');
const session = require('express-session'); // install if provider is session
const { ssoMiddleware, ssoRouterUrl } = require('@megaads/express-sso-client');

const app = express();
app.use(session({ /* your config */ }));

// please contact CTO MegaAds get configuration:
const ssoOptions = {
  active: true,
  provider: 'session' || 'jwt', // if provider is 'jwt' via header 'x-access-token' or 'authorization'
  token_options: {},        // set if provider is 'jwt'
  secret: 'random_string',  // set if provider is 'jwt'
  app_id: XXXX,
  login_url: 'https://.../system/home/login', 
  logout_url: 'https://.../system/home/logout',
  callback_url: 'http://localhost:3000/sso/callback', // my domain
  auth_url: 'https://.../auth/sso', 
  redirect_url: 'http://localhost:3000', // set if provider is 'session'
};

app.use(ssoMiddleware(ssoOptions, ['/admin']));
app.use(ssoRouterUrl(ssoOptions));

app.get('/admin', (req, res) => {
  // handler
  res.send(`Admin, ${JSON.stringify(req.user)}`);
});

app.get('/', (req, res) => {
  res.send(`Hello, Guest!`);
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});

```

## Contact
- Email: kieutuananh1995@gmail.com
- Skype: tuananhzippy

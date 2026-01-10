# onelyid-local

**Install:**

```sh
npm install onelyid
```

**Usage:**

```js
import express from 'express'
import { onelyidMiddleware } from 'onelyid'

const app = express()
app.use(onelyidMiddleware())
```

That's it!  
Now, you can visit `/oauth` route on your **express** app (e.g. `http://localhost:3000/oauth`) to see all the supported endpoints.

In particular, we have the following endpoints:
|      Purpose      |  Endpoint                        |
|-------------------|----------------------------------|
| **_Auth status_** | `/oauth/userinfo`                |
| **_Login_**       | `/oauth/login?handle=abraj.dev`  |
| **_Logout_**      | `/oauth/logout`                  |

**NOTE:**
- For the login endpoint, _**handle**_ must be a _domain handle_ which supports [**AT Protocol**](https://atproto.com/) login, e.g. your [Bluesky](https://bsky.app/) handle
- By default, the **onelyid middleware** is _mounted_ on `/oauth` route. However, you can customize routes using the following options:

```js
app.use(onelyidMiddleware({ mountPath: '/auth' }))
```
or
```js
app.use('/auth', onelyidMiddleware())
```

**References:**
- https://atproto.com/guides/applications
- https://github.com/bluesky-social/atproto/discussions/2656
- https://github.com/bluesky-social/proposals/blob/main/0004-oauth/README.md
- https://github.com/bluesky-social/proposals/blob/main/0011-auth-scopes/README.md
- https://atproto.com/specs/oauth
- https://atproto.com/specs/permission
- https://docs.bsky.app/docs/advanced-guides/oauth-client
- https://github.com/bluesky-social/atproto/discussions/3950

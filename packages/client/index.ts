import express, { type Router } from 'express'
import { OAuthResolverError } from '@atproto/oauth-client-node'
import { isValidHandle } from '@atproto/syntax'
import { createDb, migrateToLatest } from '#/packages/db'
import { getOrCreateCookieSecret } from '#/packages/db/queries'
import { createClient } from './oauth-client'
import { createBidirectionalResolver, createIdResolver } from './id-resolver'
import { getSession, getSessionUser } from './session'
import { assertPath, assertPublicUrl, getConsoleLogger, getDatabasePath } from './utils'
import { AppContext, OnelyidConfig, RespGlobals } from './types'
import { DEFAULT_MOUNT_PATH, INVALID } from './const'

// Helper function for defining routes
const handler =
  (fn: express.Handler) =>
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      await fn(req, res, next)
    } catch (err) {
      next(err)
    }
  }

export const onelyidMiddleware = (config?: OnelyidConfig): Router => {
  const router = express.Router()

  const globals: RespGlobals = {
    // initialized on mount
    cookieSecret: '',
    publicUrl: '',  // possibly updated on first request
    mountPath: '',

    // initialized on first request
    baseUrl: '',
    prefixPath: '',
    prefixRoute: '',
    basePath: '',
  }

  globals.cookieSecret = config?.cookieSecret ?? '';
  globals.publicUrl = assertPublicUrl(config?.publicUrl);
  globals.mountPath = assertPath(config?.mountPath);

  let initError: unknown = null
  let routesRegistered = false
  const ctx: AppContext = {
    logger: config?.logger ?? getConsoleLogger(),
    db: null,
    oauthClient: null,
    resolver: null,
  };

  // kick off async initialization immediately
  ;(async () => {
    try {
      const dbPath = config?.dbPath || getDatabasePath()
      ctx.db = createDb(dbPath)
      await migrateToLatest(ctx.db)

      if (!globals.cookieSecret) {
        globals.cookieSecret = await getOrCreateCookieSecret(ctx.db)
      }

      const baseIdResolver = createIdResolver()
      ctx.resolver = createBidirectionalResolver(baseIdResolver)
    } catch (err) {
      initError = err
    }
  })()

  // gate middleware
  router.use(async (req, res, next) => {
    if (initError) {
      return next(initError)
    }
    if (!ctx.db || !globals.cookieSecret || !ctx.resolver) {
      return res.status(503).send('Service initializing')
    }

    if (!globals.publicUrl) {
      const host = req.get('host')
      const detectedPublicUrl = assertPublicUrl(`${req.protocol}://${host}`)
      if (detectedPublicUrl) {
        globals.publicUrl = detectedPublicUrl
        globals.baseUrl = globals.publicUrl
      } else {
        const port = host?.split(':')[1] ?? ''
        globals.baseUrl = `http://127.0.0.1${port === '80' ? '' : `:${port}`}`
      }
    }

    if (globals.publicUrl === INVALID) {
      return res.status(503).send('Invalid publicUrl provided! Valid example: https://example.com')
    }

    if (!globals.basePath) {
      const baseUrl = req.baseUrl;
      if (baseUrl) {
        globals.prefixPath = `${baseUrl}${globals.mountPath}`;
        globals.prefixRoute = globals.mountPath;
      } else {
        globals.prefixPath = globals.mountPath || DEFAULT_MOUNT_PATH;
        globals.prefixRoute = globals.prefixPath
      }
      globals.basePath = `${globals.baseUrl}${globals.prefixPath}`  
    }

    if (!routesRegistered) {
      registerRoutes(router, ctx, globals, config)
      routesRegistered = true;
    }

    if (!ctx.oauthClient) {
      ctx.oauthClient = await createClient(ctx, globals)
    }

    // custom json response
    res.json = (data: unknown) => sendJson(res, data)

    next()
  })

  return router
}

function registerRoutes(router: Router, ctx: AppContext, globals: RespGlobals, config?: OnelyidConfig) {
  // OAuth metadata
  router.get(
    `${globals.prefixRoute}/client-metadata.json`,
    handler((_req, res) => {
      return res.json(ctx.oauthClient!.clientMetadata)
    })
  )

  // OAuth callback to complete session creation
  router.get(
    `${globals.prefixRoute}/callback`,
    handler(async (req, res) => {
      const params = new URLSearchParams(req.originalUrl.split('?')[1])
      try {
        const { session } = await ctx.oauthClient!.callback(params)
        const clientSession = await getSession(req, res, globals.cookieSecret);
        // assert(!clientSession.did, 'session already exists')
        clientSession.did = session.did
        await clientSession.save()
      } catch (err) {
        ctx.logger.error({ err }, 'oauth callback failed')
        return res.redirect('/?error')
      }

      const loginRedirect = assertPath(config?.loginRedirect) || `${globals.prefixPath}/userinfo`
      return res.redirect(loginRedirect)
    })
  )

  // Login handler
  router.get(
    `${globals.prefixRoute}/login`,
    handler(async (req, res) => {
      // Validate
      const handle = req.query.handle as string
      if (typeof handle !== 'string' || !isValidHandle(handle)) {
        return res.json({ handle: `${handle ?? ''}`, error: 'invalid handle' })
      }

      // Initiate the OAuth flow
      try {
        const url = await ctx.oauthClient!.authorize(handle, {
          scope: 'atproto transition:generic',
        })
        return res.redirect(url.toString())
      } catch (err) {
        ctx.logger.error({ err }, 'oauth authorize failed')
        return res.json({
          error:
            err instanceof OAuthResolverError
              ? err.message
              : "couldn't initiate login",
        })
      }
    })
  )

  // User info for current session
  router.get(
    `${globals.prefixRoute}/userinfo`,
    handler(async (req, res) => {
      const { user, error } = await getSessionUser(req, res, ctx, globals.cookieSecret)
      if (user === null) {
        return res.json({ user, info: 'not logged-in' })
      } else if (!user) {
        return res.json({ user: null, error })
      }
      return res.json({ user })
    })
  )
}

function sendJson(res: express.Response, data: unknown) {
  const dataStr = JSON.stringify(data, null, 2)
  return res.type('json').send(dataStr)
}

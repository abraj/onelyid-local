import express, { type Router } from 'express'
import { OAuthResolverError } from '@atproto/oauth-client-node'
import { isValidHandle } from '@atproto/syntax'
import { createDb, migrateToLatest } from '../db'
import { createClient } from './oauth-client'
import { createBidirectionalResolver, createIdResolver } from './id-resolver'
import { getSession, getSessionUser } from './session'
import { assertPath, assertPublicUrl } from './utils'
import { AppContext, OnelyidConfig, RespGlobals } from './types'
import { DEFAULT_LOCAL_PORT, DEFAULT_MOUNT_PATH, DEMO_HANDLE, INVALID } from './const'

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

export const onelyidMiddleware = (config: OnelyidConfig): Router => {
  const router = express.Router()

  const globals: RespGlobals = {
    // initialized on mount
    publicUrl: '',  // possibly updated on first request
    localPort: '',
    mountPath: '',
    baseUrl: '',

    // initialized on first request
    prefixPath: '',
    prefixRoute: '',
    basePath: '',
  }

  globals.publicUrl = assertPublicUrl(config.publicUrl);
  globals.localPort = `${config.port ?? DEFAULT_LOCAL_PORT}`;
  globals.mountPath = assertPath(config.mountPath);
  globals.baseUrl = globals.publicUrl || `http://127.0.0.1${globals.localPort === '80' ? '' : `:${globals.localPort}`}`

  const { dbPath, logger } = config

  let initError: unknown = null
  let routesRegistered = false
  const ctx: AppContext = {
    logger,
    db: null,
    oauthClient: null,
    resolver: null,
  };

  // kick off async initialization immediately
  ;(async () => {
    try {
      ctx.db = createDb(dbPath)
      await migrateToLatest(ctx.db)

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
    if (globals.publicUrl === INVALID) {
      return res.status(503).send('Invalid publicUrl provided! Valid example: https://example.com')
    }
    if (!ctx.db || !ctx.resolver) {
      return res.status(503).send('Service initializing')
    }

    if (!globals.publicUrl) {
      const detectedPublicUrl = assertPublicUrl(`${req.protocol}://${req.get('host')}`)
      globals.publicUrl = detectedPublicUrl
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

function registerRoutes(router: Router, ctx: AppContext, globals: RespGlobals, config: OnelyidConfig) {
  const demoHandle = DEMO_HANDLE;

  const login = `${globals.basePath}/login?handle=${demoHandle}`;
  const logout = `${globals.basePath}/logout`;
  const userinfo = `${globals.basePath}/userinfo`;

  // OAuth metadata
  router.get(
    `${globals.prefixRoute}/client-metadata.json`,
    handler((_req, res) => {
      return res.json(ctx.oauthClient!.clientMetadata)
    })
  )

  // Middleware root
  router.get(
    `${globals.prefixRoute ?? '/'}`,
    handler((_req, res) => {
      return res.json({
        info: "middleware root endpoint",
        try: [{ login, logout, userinfo }],
      })
    })
  )

  // OAuth callback to complete session creation
  router.get(
    `${globals.prefixRoute}/callback`,
    handler(async (req, res) => {
      const params = new URLSearchParams(req.originalUrl.split('?')[1])
      try {
        const { session } = await ctx.oauthClient!.callback(params)
        const clientSession = await getSession(req, res, config.cookieSecret);
        // assert(!clientSession.did, 'session already exists')
        clientSession.did = session.did
        await clientSession.save()
      } catch (err) {
        ctx.logger.error({ err }, 'oauth callback failed')
        return res.redirect('/?error')
      }

      const loginRedirect = assertPath(config.loginRedirect) || `${globals.prefixPath}/userinfo`
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
        return res.json({
          handle: `${handle ?? ''}`,
          error: 'invalid handle',
          try: [{ login }],
        })
      }

      // Initiate the OAuth flow
      try {
        const url = await ctx.oauthClient!.authorize(handle, {
          scope: 'atproto transition:email',
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

  // Logout handler
  // TODO: Can make it as POST later, with an info message on GET
  router.all(
    `${globals.prefixRoute}/logout`,
    handler(async (req, res) => {
      const session = await getSession(req, res, config.cookieSecret);
      await session.destroy()
      return res.redirect('/')
    })
  )

  // User info for current session
  router.get(
    `${globals.prefixRoute}/userinfo`,
    handler(async (req, res) => {
      const { user, error } = await getSessionUser(req, res, ctx, config.cookieSecret)
      if (user === null) {
        return res.json({ user, try: [{ login }] })
      } else if (!user) {
        return res.json({ user: null, error, try: [{ login }] })
      }
      return res.json({ user, try: [{ logout }] })
    })
  )
}

function sendJson(res: express.Response, data: unknown) {
  const dataStr = JSON.stringify(data, null, 2)
  return res.type('json').send(dataStr)
}

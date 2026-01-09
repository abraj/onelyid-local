import { NodeOAuthClient } from '@atproto/oauth-client-node'
import type { AppContext, RespGlobals } from './types'
import { SessionStore, StateStore } from './storage'

export const createClient = async (ctx: AppContext, globals: RespGlobals) => {
  const enc = encodeURIComponent
  return new NodeOAuthClient({
    clientMetadata: {
      client_name: 'AT Protocol Express App',
      client_id: globals.publicUrl
        ? `${globals.basePath}/client-metadata.json`
        : `http://localhost?redirect_uri=${enc(`${globals.basePath}/callback`)}&scope=${enc('atproto transition:generic transition:email')}`,
      client_uri: globals.baseUrl,
      redirect_uris: [`${globals.basePath}/callback`],
      scope: 'atproto transition:generic transition:email',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
      token_endpoint_auth_method: 'none',
      dpop_bound_access_tokens: true,
    },
    stateStore: new StateStore(ctx.db!),
    sessionStore: new SessionStore(ctx.db!),
  })
}

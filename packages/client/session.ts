import type { IncomingMessage, ServerResponse } from 'node:http'
import { Agent } from '@atproto/api'
import { OAuthServerAgent } from '@atproto/oauth-client-node'
import { getIronSession } from 'iron-session'
import { AppContext, ProfileView, Session } from './types'
import * as Profile from '#/generated/lexicon/types/app/bsky/actor/profile'
import dataTrusted from '#/packages/data/trusted.json'

export async function getSession(
  req: IncomingMessage,
  res: ServerResponse<IncomingMessage>,
  cookieSecret: string,
) {
  const session = await getIronSession<Session>(req, res, {
    cookieName: 'sid',
    password: cookieSecret,
  })
  return session;
}

// Helper function to get the Atproto Agent for the active session
export async function getSessionAgent(
  req: IncomingMessage,
  res: ServerResponse<IncomingMessage>,
  ctx: AppContext,
  cookieSecret: string,
): Promise<{ agent?: Agent | null, issuer?: string, error?: string }> {
  const session = await getSession(req, res, cookieSecret);
  if (!session.did) return { agent: null }
  try {
    const oauthSession = await ctx.oauthClient!.restore(session.did)

    let issuer: OAuthServerAgent['issuer'] | null = oauthSession.server.issuer;
    if (!issuer || issuer !== oauthSession.serverMetadata.issuer) {
      return { error: 'invalid issuer' }
    }

    const agent = oauthSession ? new Agent(oauthSession) : null
    return { agent, issuer }
  } catch (err) {
    const error = 'oauth restore failed'
    ctx.logger.warn({ err }, error)
    await session.destroy()
    return { error }
  }
}

export async function getSessionUser(
    req: IncomingMessage,
    res: ServerResponse<IncomingMessage>,
    ctx: AppContext,
    cookieSecret: string,
): Promise<{ user?: ProfileView | null, error?: string }> {
  // If the user is signed in, get an agent which communicates with their server
  const { agent, issuer } = await getSessionAgent(req, res, ctx, cookieSecret);

  if (!agent || !issuer) {
    return { user: null }
  }

  const issuerTrusted = dataTrusted.trustedIssuers.includes(issuer)

  // Fetch user info (current auth session)
  const userSessionPr = agent.com.atproto.server.getSession().catch(() => undefined);

  // Fetch additional information about the logged-in user
  const profileResponsePr = agent.com.atproto.repo.getRecord({
    repo: agent.assertDid,
    collection: 'app.bsky.actor.profile',
    rkey: 'self',
  }).catch(() => undefined);

  const [userSession, profileResponse] = await Promise.all([userSessionPr, profileResponsePr]);

  const profileRecord = profileResponse?.data;
  const userInfo = userSession?.data;

  const profile: Profile.Record | null = profileRecord &&
    Profile.isRecord(profileRecord.value) &&
    Profile.validateRecord(profileRecord.value).success
      ? profileRecord.value
      : null

  const handle = userInfo?.handle;
  const email = userInfo?.email;
  const emailConfirmed = userInfo?.emailConfirmed;

  // TODO: email verification in case of untrusted issuer
  const emailTrusted = issuerTrusted;

  if (!handle) {
    const error = 'handle missing'
    ctx.logger.error(error)
    ctx.logger.warn('userSession:', userSession)
    return { error }
  }

  if (!email || !emailConfirmed) {
    const error = 'no verified email found'
    ctx.logger.error(error)
    return { error }
  }

  const profileData: ProfileView = {
    did: agent.assertDid,
    handle,
    email,
    emailTrusted,
    displayName: profile?.displayName ?? '',
    avatar: 'BlobRef{ref,mimeType,size,original}', // profile.avatar
    // profile.createdAt
    // profile.description
  };

  return { user: profileData }
}

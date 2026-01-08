import type { IncomingMessage, ServerResponse } from 'node:http'
import { Agent } from '@atproto/api'
import { OAuthServerAgent } from '@atproto/oauth-client-node'
import { getIronSession } from 'iron-session'
import { AppContext, ProfileView, Session } from './types'
import * as Profile from '#/generated/lexicon/types/app/bsky/actor/profile'

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
  const { agent } = await getSessionAgent(req, res, ctx, cookieSecret);

  if (!agent) {
    return { user: null }
  }

  // Fetch user's domain handle
  const handlePr = ctx.resolver!.resolveDidToHandle(agent.assertDid);

  // Fetch additional information about the logged-in user
  const profileResponsePr = agent.com.atproto.repo.getRecord({
    repo: agent.assertDid,
    collection: 'app.bsky.actor.profile',
    rkey: 'self',
  }).catch(() => undefined);

  const [handle, profileResponse] = await Promise.all([handlePr, profileResponsePr]);

  const profileRecord = profileResponse?.data;

  const profile: Profile.Record | null = profileRecord &&
    Profile.isRecord(profileRecord.value) &&
    Profile.validateRecord(profileRecord.value).success
      ? profileRecord.value
      : null

  const profileData: ProfileView = {
    did: agent.assertDid,
    handle,
    displayName: profile?.displayName ?? '',
    avatar: 'BlobRef{ref,mimeType,size,original}', // profile.avatar
    // profile.createdAt
    // profile.description
  };

  return { user: profileData }
}

import type { IncomingMessage, ServerResponse } from 'node:http'
import { getIronSession } from 'iron-session'
import { Session } from './types'

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

import { OAuthClient } from '@atproto/oauth-client-node'
import type { Database } from '#/packages/db';

export type { Database } from '../db'

export type Logger = {
  info: Function;
  warn: Function;
  error: Function;
}

export type Session = { did: string }

export type OnelyidConfig = {
  dbPath?: string;
  cookieSecret: string;
  publicUrl?: string;
  logger?: Logger;
  mountPath?: string;
  loginRedirect?: string;
}

export type RespGlobals = {
  publicUrl: string;
  mountPath: string;
  baseUrl: string;
  prefixPath: string;
  prefixRoute: string;
  basePath: string;
}

// Application state passed to the router and elsewhere
export type AppContext = {
  logger: Logger;
  db: Database | null;
  oauthClient: OAuthClient | null;
};

import crypto from 'node:crypto'
import type { Database } from '#/packages/db';
import { COOKIE_SECRET_KEY } from '#/packages/client/const';

export async function getOrCreateCookieSecret(db: Database) {
  const existing = await db
    .selectFrom('app_secrets')
    .select('value')
    .where('key', '=', COOKIE_SECRET_KEY)
    .executeTakeFirst()

  if (existing) {
    return existing.value
  }

  const secret = crypto.randomBytes(32).toString('hex')

  await db
    .insertInto('app_secrets')
    .values({
      key: COOKIE_SECRET_KEY,
      value: secret,
    })
    .onConflict((oc) => oc.doNothing())
    .execute()

  return secret
}

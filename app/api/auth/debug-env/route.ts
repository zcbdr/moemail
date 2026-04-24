import { getRequestContext } from '@cloudflare/next-on-pages'

export const runtime = 'edge'

export async function GET() {
  const env = getRequestContext().env as CloudflareEnv & Record<string, string | undefined>
  return Response.json({
    AUTH_SECRET: { present: Boolean(env.AUTH_SECRET), length: env.AUTH_SECRET?.length || 0 },
    AUTH_GITHUB_ID: { present: Boolean(env.AUTH_GITHUB_ID), length: env.AUTH_GITHUB_ID?.length || 0 },
    AUTH_GITHUB_SECRET: { present: Boolean(env.AUTH_GITHUB_SECRET), length: env.AUTH_GITHUB_SECRET?.length || 0 },
    AUTH_URL: { present: Boolean(env.AUTH_URL), value: env.AUTH_URL || null },
    NEXTAUTH_URL: { present: Boolean(env.NEXTAUTH_URL), value: env.NEXTAUTH_URL || null },
    AUTH_TRUST_HOST: { present: Boolean(env.AUTH_TRUST_HOST), value: env.AUTH_TRUST_HOST || null },
  })
}

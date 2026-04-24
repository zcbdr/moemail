interface Env {
  DB: D1Database
  SITE_CONFIG: KVNamespace
}

type Role = 'emperor' | 'duke' | 'knight' | 'civilian'

const DEFAULT_MAX_EMAILS = '20'
const DEFAULT_DOMAIN = 'moemail.app'
const DEFAULT_LIMITS: Record<Role, number> = {
  emperor: 0,
  duke: 5,
  knight: 2,
  civilian: -1,
}

function json(body: unknown, init: ResponseInit = {}, timings: string[] = [], startedAt = Date.now()) {
  const headers = new Headers(init.headers)
  headers.set('content-type', 'application/json; charset=utf-8')
  headers.set('Server-Timing', [...timings, `total;dur=${Date.now() - startedAt}`].join(', '))
  return new Response(JSON.stringify(body), { ...init, headers })
}

function corsHeaders(request: Request) {
  const origin = request.headers.get('Origin')
  const headers = new Headers()
  if (origin) headers.set('Access-Control-Allow-Origin', origin)
  headers.set('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization')
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  headers.set('Access-Control-Allow-Credentials', 'true')
  return headers
}

async function getUserIdByApiKey(env: Env, request: Request, timings: string[]) {
  const apiKey = request.headers.get('X-API-Key')
  if (!apiKey) return null

  const startedAt = Date.now()
  const row = await env.DB.prepare(
    'SELECT user_id AS userId FROM api_keys WHERE key = ? AND enabled = 1 AND expires_at > ? LIMIT 1'
  ).bind(apiKey, Math.floor(Date.now() / 1000)).first<{ userId: string }>()
  timings.push(`api-key;dur=${Date.now() - startedAt}`)
  return row?.userId || null
}

async function getUserRoles(env: Env, userId: string, timings: string[]): Promise<Role[]> {
  const startedAt = Date.now()
  const { results } = await env.DB.prepare(
    'SELECT r.name AS name FROM user_role ur INNER JOIN role r ON ur.role_id = r.id WHERE ur.user_id = ?'
  ).bind(userId).all<{ name: Role }>()
  timings.push(`roles;dur=${Date.now() - startedAt}`)
  return (results || []).map((r) => r.name)
}

function bestRole(roles: Role[]) {
  if (roles.includes('emperor')) return 'emperor'
  if (roles.includes('duke')) return 'duke'
  if (roles.includes('knight')) return 'knight'
  if (roles.includes('civilian')) return 'civilian'
  return 'civilian'
}

async function handleConfig(env: Env, timings: string[], startedAt: number) {
  const kvStartedAt = Date.now()
  const [defaultRole, emailDomains, adminContact, maxEmails] = await Promise.all([
    env.SITE_CONFIG.get('DEFAULT_ROLE'),
    env.SITE_CONFIG.get('EMAIL_DOMAINS'),
    env.SITE_CONFIG.get('ADMIN_CONTACT'),
    env.SITE_CONFIG.get('MAX_EMAILS'),
  ])
  timings.push(`kv;dur=${Date.now() - kvStartedAt}`)

  const headers = new Headers({
    'Cache-Control': 'public, max-age=60, stale-while-revalidate=300',
  })
  return json({
    defaultRole: defaultRole || 'civilian',
    emailDomains: emailDomains || DEFAULT_DOMAIN,
    adminContact: adminContact || '',
    maxEmails: maxEmails || DEFAULT_MAX_EMAILS,
  }, { headers }, timings, startedAt)
}

async function handleEmails(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  const url = new URL(request.url)
  const includeTotal = url.searchParams.get('includeTotal') === '1'
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') || '20'), 1), 100)

  const now = Date.now()
  const queryStartedAt = Date.now()
  const { results } = await env.DB.prepare(
    'SELECT id, address, userId, created_at AS createdAt, expires_at AS expiresAt FROM email WHERE userId = ? AND expires_at > ? ORDER BY created_at DESC, id DESC LIMIT ?'
  ).bind(userId, now, limit + 1).all()
  timings.push(`db-list;dur=${Date.now() - queryStartedAt}`)

  let total: number | undefined
  if (includeTotal) {
    const totalStartedAt = Date.now()
    const row = await env.DB.prepare(
      'SELECT count(*) AS count FROM email WHERE userId = ? AND expires_at > ?'
    ).bind(userId, now).first<{ count: number }>()
    total = Number(row?.count || 0)
    timings.push(`db-total;dur=${Date.now() - totalStartedAt}`)
  }

  const rows = results || []
  const hasMore = rows.length > limit
  return json({
    emails: hasMore ? rows.slice(0, limit) : rows,
    nextCursor: null,
    ...(includeTotal ? { total } : {}),
  }, {}, timings, startedAt)
}

async function handleMessages(env: Env, request: Request, userId: string, emailId: string, timings: string[], startedAt: number) {
  const url = new URL(request.url)
  const messageType = url.searchParams.get('type')
  const includeTotal = url.searchParams.get('includeTotal') === '1'
  const limit = Math.min(Math.max(Number(url.searchParams.get('limit') || '20'), 1), 100)

  const dbStartedAt = Date.now()
  const [email, messagesResult] = await Promise.all([
    env.DB.prepare('SELECT id FROM email WHERE id = ? AND userId = ? LIMIT 1').bind(emailId, userId).first(),
    messageType === 'sent'
      ? env.DB.prepare('SELECT id, from_address, to_address, subject, content, html, sent_at, received_at FROM message WHERE emailId = ? AND type = ? ORDER BY sent_at DESC, id DESC LIMIT ?').bind(emailId, 'sent', limit + 1).all()
      : env.DB.prepare('SELECT id, from_address, to_address, subject, content, html, sent_at, received_at FROM message WHERE emailId = ? AND (type != ? OR type IS NULL) ORDER BY received_at DESC, id DESC LIMIT ?').bind(emailId, 'sent', limit + 1).all(),
  ])
  timings.push(`db;dur=${Date.now() - dbStartedAt}`)

  if (!email) return json({ error: '无权限查看' }, { status: 403 }, timings, startedAt)

  let total: number | undefined
  if (includeTotal) {
    const totalStartedAt = Date.now()
    const row = await (messageType === 'sent'
      ? env.DB.prepare('SELECT count(*) AS count FROM message WHERE emailId = ? AND type = ?').bind(emailId, 'sent')
      : env.DB.prepare('SELECT count(*) AS count FROM message WHERE emailId = ? AND (type != ? OR type IS NULL)').bind(emailId, 'sent')
    ).first<{ count: number }>()
    total = Number(row?.count || 0)
    timings.push(`db-total;dur=${Date.now() - totalStartedAt}`)
  }

  const rows = messagesResult.results || []
  const hasMore = rows.length > limit
  return json({
    messages: (hasMore ? rows.slice(0, limit) : rows).map((msg: any) => ({
      id: msg.id,
      from_address: msg.from_address,
      to_address: msg.to_address,
      subject: msg.subject,
      content: msg.content,
      html: msg.html,
      sent_at: msg.sent_at,
      received_at: msg.received_at,
    })),
    nextCursor: null,
    ...(includeTotal ? { total } : {}),
  }, {}, timings, startedAt)
}

async function handleSendPermission(env: Env, userId: string, timings: string[], startedAt: number) {
  const kvStartedAt = Date.now()
  const enabled = await env.SITE_CONFIG.get('EMAIL_SERVICE_ENABLED')
  timings.push(`kv;dur=${Date.now() - kvStartedAt}`)
  if (enabled !== 'true') {
    return json({ canSend: false, error: '邮件发送服务未启用' }, {}, timings, startedAt)
  }

  const roles = await getUserRoles(env, userId, timings)
  const role = bestRole(roles)
  const limit = DEFAULT_LIMITS[role]
  if (limit === -1) return json({ canSend: false, error: '您的角色没有发件权限' }, {}, timings, startedAt)
  if (limit === 0) return json({ canSend: true }, {}, timings, startedAt)

  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const countStartedAt = Date.now()
  const row = await env.DB.prepare(
    'SELECT count(*) AS count FROM message m INNER JOIN email e ON m.emailId = e.id WHERE e.userId = ? AND m.type = ? AND m.received_at >= ?'
  ).bind(userId, 'sent', today.getTime()).first<{ count: number }>()
  const sent = Number(row?.count || 0)
  timings.push(`db-count;dur=${Date.now() - countStartedAt}`)
  return json({ canSend: sent < limit, remainingEmails: Math.max(0, limit - sent) }, {}, timings, startedAt)
}

async function handleGenerate(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  let body: { name?: string; expiryTime?: number; domain?: string }
  try {
    body = await request.json()
  } catch {
    return json({ error: 'Invalid JSON' }, { status: 400 }, timings, startedAt)
  }

  const expiryTime = Number(body.expiryTime)
  if (![3600000, 86400000, 259200000, 0].includes(expiryTime)) {
    return json({ error: '无效的过期时间' }, { status: 400 }, timings, startedAt)
  }

  const rolePromise = getUserRoles(env, userId, timings)
  const kvStartedAt = Date.now()
  const [domainString, maxEmails] = await Promise.all([
    env.SITE_CONFIG.get('EMAIL_DOMAINS'),
    env.SITE_CONFIG.get('MAX_EMAILS'),
  ])
  timings.push(`kv;dur=${Date.now() - kvStartedAt}`)

  const domains = domainString ? domainString.split(',') : [DEFAULT_DOMAIN]
  const domain = body.domain || domains[0]
  if (!domains.includes(domain)) return json({ error: '无效的域名' }, { status: 400 }, timings, startedAt)

  const roles = await rolePromise
  const role = bestRole(roles)
  if (role !== 'emperor') {
    const quotaStartedAt = Date.now()
    const row = await env.DB.prepare(
      'SELECT count(*) AS count FROM email WHERE userId = ? AND expires_at > ?'
    ).bind(userId, Date.now()).first<{ count: number }>()
    timings.push(`quota;dur=${Date.now() - quotaStartedAt}`)
    if (Number(row?.count || 0) >= Number(maxEmails || DEFAULT_MAX_EMAILS)) {
      return json({ error: `已达到最大邮箱数量限制 (${maxEmails || DEFAULT_MAX_EMAILS})` }, { status: 403 }, timings, startedAt)
    }
  }

  const id = crypto.randomUUID()
  const local = body.name || crypto.randomUUID().replace(/-/g, '').slice(0, 8)
  const address = `${local}@${domain}`
  const now = Date.now()
  const expiresAt = expiryTime === 0 ? Date.parse('9999-01-01T00:00:00.000Z') : now + expiryTime

  try {
    const insertStartedAt = Date.now()
    await env.DB.prepare(
      'INSERT INTO email (id, address, userId, created_at, expires_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(id, address, userId, now, expiresAt).run()
    timings.push(`insert;dur=${Date.now() - insertStartedAt}`)
    return json({ id, email: address }, {}, timings, startedAt)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (message.toLowerCase().includes('unique') || message.toLowerCase().includes('constraint')) {
      return json({ error: '该邮箱地址已被使用' }, { status: 409 }, timings, startedAt)
    }
    return json({ error: '创建邮箱失败' }, { status: 500 }, timings, startedAt)
  }
}

export default {
  async fetch(request: Request, env: Env) {
    const startedAt = Date.now()
    const timings: string[] = []
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(request) })

    const url = new URL(request.url)
    const path = url.pathname

    try {
      if (request.method === 'GET' && path === '/api/config') {
        const res = await handleConfig(env, timings, startedAt)
        const headers = new Headers(res.headers)
        for (const [k, v] of corsHeaders(request)) headers.set(k, v)
        return new Response(res.body, { status: res.status, headers })
      }

      const userId = await getUserIdByApiKey(env, request, timings)
      if (!userId) return json({ error: '无效的 API Key' }, { status: 401 }, timings, startedAt)

      let response: Response | null = null
      if (request.method === 'GET' && path === '/api/emails') response = await handleEmails(env, request, userId, timings, startedAt)
      else if (request.method === 'GET' && path === '/api/emails/send-permission') response = await handleSendPermission(env, userId, timings, startedAt)
      else if (request.method === 'POST' && path === '/api/emails/generate') response = await handleGenerate(env, request, userId, timings, startedAt)
      else {
        const match = path.match(/^\/api\/emails\/([^/]+)$/)
        if (request.method === 'GET' && match) response = await handleMessages(env, request, userId, match[1], timings, startedAt)
      }

      if (!response) return json({ error: 'Not found' }, { status: 404 }, timings, startedAt)
      const headers = new Headers(response.headers)
      for (const [k, v] of corsHeaders(request)) headers.set(k, v)
      return new Response(response.body, { status: response.status, headers })
    } catch (error) {
      console.error('API worker error:', error)
      return json({ error: 'Internal error' }, { status: 500 }, timings, startedAt)
    }
  }
}

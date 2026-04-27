interface Env {
  DB: D1Database
  SITE_CONFIG: KVNamespace
  AUTH_SECRET: string
  PAGES_ORIGIN?: string
}

type Role = 'emperor' | 'duke' | 'knight' | 'civilian'
type Permission = 'manage_email' | 'manage_webhook' | 'promote_user' | 'manage_config' | 'manage_api_key'

const DEFAULT_MAX_EMAILS = '20'
const DEFAULT_DOMAIN = 'moemail.app'
const DEFAULT_LIMITS: Record<Role, number> = {
  emperor: 0,
  duke: 5,
  knight: 2,
  civilian: -1,
}


const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  emperor: ['manage_email', 'manage_webhook', 'promote_user', 'manage_config', 'manage_api_key'],
  duke: ['manage_email', 'manage_webhook', 'manage_api_key'],
  knight: ['manage_email', 'manage_webhook'],
  civilian: [],
}

function roleHasPermission(roles: Role[], permission: Permission) {
  return roles.some((role) => ROLE_PERMISSIONS[role]?.includes(permission))
}

async function requirePermission(env: Env, userId: string, permission: Permission, timings: string[], startedAt: number) {
  const roles = await getUserRoles(env, userId, timings)
  if (!roleHasPermission(roles, permission)) return json({ error: '权限不足' }, { status: 403 }, timings, startedAt)
  return null
}

async function safeJson<T>(request: Request): Promise<T | null> { try { return await request.json() as T } catch { return null } }

function randomApiKey() {
  const bytes = new Uint8Array(24); crypto.getRandomValues(bytes)
  let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte)
  return `mk_${btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`
}


const MAX_SUBJECT_LENGTH = 200
const MAX_CONTENT_LENGTH = 100_000
const MAX_TO_LENGTH = 320

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
  headers.set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS')
  headers.set('Access-Control-Allow-Credentials', 'true')
  return headers
}

function getPagesOrigin(env: Env) {
  const origin = env.PAGES_ORIGIN?.trim()
  if (!origin) return null
  try {
    return new URL(origin).origin
  } catch {
    return null
  }
}

async function proxyToPages(env: Env, request: Request) {
  const pagesOrigin = getPagesOrigin(env)
  if (!pagesOrigin) return json({ error: 'PAGES_ORIGIN is not configured' }, { status: 500 })

  const url = new URL(request.url)
  const target = new URL(url.pathname + url.search, pagesOrigin)
  const headers = new Headers(request.headers)

  // Keep the public origin visible to NextAuth/Auth.js so generated signin and
  // callback URLs use the configured custom domain instead of the Pages subdomain.
  headers.set('Host', url.host)
  headers.set('X-Forwarded-Host', url.host)
  headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''))
  headers.set('X-Forwarded-Port', url.protocol === 'https:' ? '443' : '80')

  const response = await fetch(new Request(target, {
    method: request.method,
    headers,
    body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
    redirect: 'manual',
  }))

  const publicOrigin = url.origin
  const responseHeaders = new Headers(response.headers)
  const location = responseHeaders.get('Location')
  if (location) {
    responseHeaders.set('Location', location
      .replaceAll(pagesOrigin, publicOrigin)
      .replaceAll(encodeURIComponent(pagesOrigin), encodeURIComponent(publicOrigin)))
  }

  const contentType = responseHeaders.get('content-type') || ''
  if (contentType.includes('application/json') || contentType.startsWith('text/')) {
    const text = await response.text()
    const rewritten = text
      .replaceAll(pagesOrigin, publicOrigin)
      .replaceAll(encodeURIComponent(pagesOrigin), encodeURIComponent(publicOrigin))
    responseHeaders.delete('content-length')
    return new Response(rewritten, { status: response.status, statusText: response.statusText, headers: responseHeaders })
  }

  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders })
}

function parseCookies(request: Request) {
  const cookie = request.headers.get('Cookie') || ''
  const out = new Map<string, string>()
  for (const part of cookie.split(';')) {
    const trimmed = part.trim()
    const index = trimmed.indexOf('=')
    if (index <= 0) continue
    out.set(trimmed.slice(0, index), decodeURIComponent(trimmed.slice(index + 1)))
  }
  return out
}

function getCookie(request: Request, name: string) {
  const cookies = parseCookies(request)
  const direct = cookies.get(name)
  if (direct) return direct

  const chunks: string[] = []
  for (let i = 0; ; i++) {
    const value = cookies.get(`${name}.${i}`)
    if (!value) break
    chunks.push(value)
  }
  return chunks.length ? chunks.join('') : null
}

function base64urlDecode(input: string) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function concatBytes(...parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false
  let out = 0
  for (let i = 0; i < a.length; i++) out |= a[i] ^ b[i]
  return out === 0
}

async function deriveAuthJsKey(secret: string, salt: string) {
  const encoder = new TextEncoder()
  const baseKey = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({
    name: 'HKDF',
    hash: 'SHA-256',
    salt: encoder.encode(salt),
    info: encoder.encode(`Auth.js Generated Encryption Key (${salt})`),
  }, baseKey, 512)
  return new Uint8Array(bits)
}

async function decodeAuthJsSessionToken(token: string, secret: string, salt: string) {
  const [protectedHeaderB64, encryptedKeyB64, ivB64, ciphertextB64, tagB64] = token.split('.')
  if (!protectedHeaderB64 || encryptedKeyB64 !== '' || !ivB64 || !ciphertextB64 || !tagB64) return null

  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(protectedHeaderB64)))
  if (header.alg !== 'dir' || header.enc !== 'A256CBC-HS512') return null

  const key = await deriveAuthJsKey(secret, salt)
  const macKey = key.slice(0, 32)
  const encKey = key.slice(32)
  const aad = new TextEncoder().encode(protectedHeaderB64)
  const iv = base64urlDecode(ivB64)
  const ciphertext = base64urlDecode(ciphertextB64)
  const tag = base64urlDecode(tagB64)
  const al = new Uint8Array(8)
  new DataView(al.buffer).setUint32(4, aad.length * 8)

  const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign'])
  const digest = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, concatBytes(aad, iv, ciphertext, al)))
  if (!timingSafeEqual(digest.slice(0, 32), tag)) return null

  const aesKey = await crypto.subtle.importKey('raw', encKey, 'AES-CBC', false, ['decrypt'])
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext)
  return JSON.parse(new TextDecoder().decode(plaintext))
}

async function getUserIdByCookie(env: Env, request: Request, timings: string[]) {
  const candidates = [
    '__Secure-authjs.session-token',
    'authjs.session-token',
    '__Secure-next-auth.session-token',
    'next-auth.session-token',
  ]

  const startedAt = Date.now()
  for (const name of candidates) {
    const token = getCookie(request, name)
    if (!token) continue
    try {
      const decoded = await decodeAuthJsSessionToken(token, env.AUTH_SECRET, name)
      if (decoded?.id && typeof decoded.id === 'string') {
        timings.push(`cookie;dur=${Date.now() - startedAt}`)
        return decoded.id
      }
    } catch {}
  }
  timings.push(`cookie;dur=${Date.now() - startedAt}`)
  return null
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

function parseRoleLimits(raw: string | null): Partial<Record<Role, number>> {
  if (!raw) return {}
  try {
    const parsed = JSON.parse(raw)
    const limits: Partial<Record<Role, number>> = {}
    for (const role of ['duke', 'knight'] as Role[]) {
      const value = Number(parsed?.[role])
      if (Number.isInteger(value) && value >= 0 && value <= 1000) limits[role] = value
    }
    return limits
  } catch {
    return {}
  }
}

async function getDailyLimit(env: Env, userId: string, timings: string[]) {
  const [roles, roleLimitsRaw] = await Promise.all([
    getUserRoles(env, userId, timings),
    env.SITE_CONFIG.get('EMAIL_ROLE_LIMITS'),
  ])
  const customLimits = parseRoleLimits(roleLimitsRaw)
  const role = bestRole(roles)
  if (role === 'emperor') return { role, limit: 0 }
  if (role === 'civilian') return { role, limit: -1 }
  return { role, limit: customLimits[role] ?? DEFAULT_LIMITS[role] }
}

async function checkSendPermission(env: Env, userId: string, timings: string[]) {
  const kvStartedAt = Date.now()
  const [enabled, resendConfigured] = await Promise.all([
    env.SITE_CONFIG.get('EMAIL_SERVICE_ENABLED'),
    env.SITE_CONFIG.get('RESEND_API_KEY'),
  ])
  timings.push(`kv;dur=${Date.now() - kvStartedAt}`)
  if (enabled !== 'true') return { canSend: false, error: '邮件发送服务未启用' }
  if (!resendConfigured) return { canSend: false, error: '邮件发送服务未配置' }

  const { limit } = await getDailyLimit(env, userId, timings)
  if (limit === -1) return { canSend: false, error: '您的角色没有发件权限' }
  if (limit === 0) return { canSend: true }

  const today = new Date()
  today.setHours(0, 0, 0, 0)
  const countStartedAt = Date.now()
  const row = await env.DB.prepare(
    'SELECT count(*) AS count FROM message m INNER JOIN email e ON m.emailId = e.id WHERE e.userId = ? AND m.type = ? AND m.sent_at >= ?'
  ).bind(userId, 'sent', today.getTime()).first<{ count: number }>()
  const sent = Number(row?.count || 0)
  timings.push(`db-count;dur=${Date.now() - countStartedAt}`)
  const remainingEmails = Math.max(0, limit - sent)
  if (sent >= limit) return { canSend: false, error: `您今天已达到发件限制 (${limit} 封)，请明天再试`, remainingEmails: 0 }
  return { canSend: true, remainingEmails }
}

async function handleSendPermission(env: Env, userId: string, timings: string[], startedAt: number) {
  return json(await checkSendPermission(env, userId, timings), {}, timings, startedAt)
}

function validateSendBody(body: any) {
  const to = typeof body?.to === 'string' ? body.to.trim() : ''
  const subject = typeof body?.subject === 'string' ? body.subject.trim() : ''
  const content = typeof body?.content === 'string' ? body.content : ''
  if (!to || !subject || !content) return { error: '收件人、主题和内容都是必填项' }
  if (to.length > MAX_TO_LENGTH || subject.length > MAX_SUBJECT_LENGTH || content.length > MAX_CONTENT_LENGTH) return { error: '邮件字段过长' }
  if (/[\r\n]/.test(to) || /[\r\n]/.test(subject)) return { error: '收件人或主题格式无效' }
  const emailPattern = /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/
  if (!emailPattern.test(to)) return { error: '收件人邮箱格式无效' }
  return { value: { to, subject, content } }
}

async function sendWithResend(apiKey: string, fromEmail: string, to: string, subject: string, content: string) {
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
    body: JSON.stringify({ from: fromEmail, to: [to], subject, html: content }),
  })
  if (!response.ok) {
    let message = 'Resend发送失败，请稍后重试'
    try {
      const data = await response.json() as { message?: string }
      if (typeof data?.message === 'string' && data.message.length <= 200) message = data.message
    } catch {}
    throw new Error(message)
  }
}

async function handleSendEmail(env: Env, request: Request, userId: string, emailId: string, timings: string[], startedAt: number) {
  let body: unknown
  try { body = await request.json() } catch { return json({ error: 'Invalid JSON' }, { status: 400 }, timings, startedAt) }
  const validated = validateSendBody(body)
  if ('error' in validated) return json({ error: validated.error }, { status: 400 }, timings, startedAt)

  const dbStartedAt = Date.now()
  const email = await env.DB.prepare(
    'SELECT id, address FROM email WHERE id = ? AND userId = ? AND expires_at > ? LIMIT 1'
  ).bind(emailId, userId, Date.now()).first<{ id: string; address: string }>()
  timings.push(`db-email;dur=${Date.now() - dbStartedAt}`)
  if (!email) return json({ error: '无权访问此邮箱' }, { status: 403 }, timings, startedAt)

  const permission = await checkSendPermission(env, userId, timings)
  if (!permission.canSend) return json({ error: permission.error, remainingEmails: permission.remainingEmails }, { status: 403 }, timings, startedAt)

  const apiKey = await env.SITE_CONFIG.get('RESEND_API_KEY')
  if (!apiKey) return json({ error: '邮件发送服务未配置' }, { status: 500 }, timings, startedAt)

  const resendStartedAt = Date.now()
  try { await sendWithResend(apiKey, email.address, validated.value.to, validated.value.subject, validated.value.content) }
  catch (error) {
    timings.push(`resend;dur=${Date.now() - resendStartedAt}`)
    return json({ error: error instanceof Error ? error.message : '发送邮件失败' }, { status: 502 }, timings, startedAt)
  }
  timings.push(`resend;dur=${Date.now() - resendStartedAt}`)

  const now = Date.now()
  const insertStartedAt = Date.now()
  await env.DB.prepare(
    'INSERT INTO message (id, emailId, from_address, to_address, subject, content, html, type, received_at, sent_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(crypto.randomUUID(), email.id, email.address, validated.value.to, validated.value.subject, '', validated.value.content, 'sent', now, now).run()
  timings.push(`db-insert;dur=${Date.now() - insertStartedAt}`)

  return json({ success: true, message: '邮件发送成功', remainingEmails: permission.remainingEmails }, {}, timings, startedAt)
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


async function handleConfigSave(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  const denied = await requirePermission(env, userId, 'manage_config', timings, startedAt); if (denied) return denied
  const body = await safeJson<{ defaultRole?: Role; emailDomains?: string; adminContact?: string; maxEmails?: string; turnstile?: { enabled?: boolean; siteKey?: string; secretKey?: string } }>(request)
  if (!body) return json({ error: 'Invalid JSON' }, { status: 400 }, timings, startedAt)
  if (!['duke', 'knight', 'civilian'].includes(body.defaultRole || '')) return json({ error: '无效的角色' }, { status: 400 }, timings, startedAt)
  const t = body.turnstile || { enabled: false, siteKey: '', secretKey: '' }
  if (t.enabled && (!t.siteKey || !t.secretKey)) return json({ error: 'Turnstile 启用时需要提供 Site Key 和 Secret Key' }, { status: 400 }, timings, startedAt)
  await Promise.all([env.SITE_CONFIG.put('DEFAULT_ROLE', body.defaultRole!), env.SITE_CONFIG.put('EMAIL_DOMAINS', body.emailDomains || ''), env.SITE_CONFIG.put('ADMIN_CONTACT', body.adminContact || ''), env.SITE_CONFIG.put('MAX_EMAILS', body.maxEmails || DEFAULT_MAX_EMAILS), env.SITE_CONFIG.put('TURNSTILE_ENABLED', String(Boolean(t.enabled))), env.SITE_CONFIG.put('TURNSTILE_SITE_KEY', t.siteKey || ''), env.SITE_CONFIG.put('TURNSTILE_SECRET_KEY', t.secretKey || '')])
  return json({ success: true }, {}, timings, startedAt)
}

async function handleConfigPrivate(env: Env, userId: string, timings: string[], startedAt: number) {
  const roles = await getUserRoles(env, userId, timings); const canManageConfig = roleHasPermission(roles, 'manage_config')
  const [defaultRole, emailDomains, adminContact, maxEmails, turnstileEnabled, turnstileSiteKey, turnstileSecretKey] = await Promise.all([env.SITE_CONFIG.get('DEFAULT_ROLE'), env.SITE_CONFIG.get('EMAIL_DOMAINS'), env.SITE_CONFIG.get('ADMIN_CONTACT'), env.SITE_CONFIG.get('MAX_EMAILS'), env.SITE_CONFIG.get('TURNSTILE_ENABLED'), env.SITE_CONFIG.get('TURNSTILE_SITE_KEY'), canManageConfig ? env.SITE_CONFIG.get('TURNSTILE_SECRET_KEY') : Promise.resolve('')])
  return json({ defaultRole: defaultRole || 'civilian', emailDomains: emailDomains || DEFAULT_DOMAIN, adminContact: adminContact || '', maxEmails: maxEmails || DEFAULT_MAX_EMAILS, turnstile: canManageConfig ? { enabled: turnstileEnabled === 'true', siteKey: turnstileSiteKey || '', secretKey: turnstileSecretKey || '' } : undefined }, {}, timings, startedAt)
}

async function handleEmailServiceConfig(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  const denied = await requirePermission(env, userId, 'manage_config', timings, startedAt); if (denied) return denied
  if (request.method === 'GET') { const [enabled, apiKey, roleLimits] = await Promise.all([env.SITE_CONFIG.get('EMAIL_SERVICE_ENABLED'), env.SITE_CONFIG.get('RESEND_API_KEY'), env.SITE_CONFIG.get('EMAIL_ROLE_LIMITS')]); const parsedLimits = parseRoleLimits(roleLimits); return json({ enabled: enabled === 'true', apiKey: apiKey || '', roleLimits: { duke: parsedLimits.duke ?? DEFAULT_LIMITS.duke, knight: parsedLimits.knight ?? DEFAULT_LIMITS.knight } }, {}, timings, startedAt) }
  const body = await safeJson<{ enabled?: boolean; apiKey?: string; roleLimits?: { duke?: number; knight?: number } }>(request)
  if (!body) return json({ error: 'Invalid JSON' }, { status: 400 }, timings, startedAt)
  if (body.enabled && !body.apiKey) return json({ error: '启用 Resend 时，API Key 为必填项' }, { status: 400 }, timings, startedAt)
  await Promise.all([env.SITE_CONFIG.put('EMAIL_SERVICE_ENABLED', String(Boolean(body.enabled))), env.SITE_CONFIG.put('RESEND_API_KEY', body.apiKey || ''), env.SITE_CONFIG.put('EMAIL_ROLE_LIMITS', JSON.stringify(body.roleLimits || {}))])
  return json({ success: true }, {}, timings, startedAt)
}

function validWebhookUrl(value: unknown) { if (typeof value !== 'string') return null; try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.toString() : null } catch { return null } }

async function handleWebhook(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  const denied = await requirePermission(env, userId, 'manage_webhook', timings, startedAt); if (denied) return denied
  if (request.method === 'GET') { const row = await env.DB.prepare('SELECT id, url, enabled, created_at AS createdAt, updated_at AS updatedAt FROM webhook WHERE user_id = ? LIMIT 1').bind(userId).first(); return json(row || { enabled: false, url: '' }, {}, timings, startedAt) }
  const body = await safeJson<{ url?: string; enabled?: boolean }>(request); const webhookUrl = validWebhookUrl(body?.url)
  if (!body || !webhookUrl || typeof body.enabled !== 'boolean') return json({ error: 'Invalid request' }, { status: 400 }, timings, startedAt)
  const now = Date.now(); const existing = await env.DB.prepare('SELECT id FROM webhook WHERE user_id = ? LIMIT 1').bind(userId).first<{ id: string }>()
  if (existing) await env.DB.prepare('UPDATE webhook SET url = ?, enabled = ?, updated_at = ? WHERE user_id = ?').bind(webhookUrl, body.enabled ? 1 : 0, now, userId).run()
  else await env.DB.prepare('INSERT INTO webhook (id, user_id, url, enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)').bind(crypto.randomUUID(), userId, webhookUrl, body.enabled ? 1 : 0, now, now).run()
  return json({ success: true }, {}, timings, startedAt)
}

async function handleWebhookTest(env: Env, request: Request, userId: string, timings: string[], startedAt: number) {
  const denied = await requirePermission(env, userId, 'manage_webhook', timings, startedAt); if (denied) return denied
  const body = await safeJson<{ url?: string }>(request); const webhookUrl = validWebhookUrl(body?.url)
  if (!webhookUrl) return json({ error: 'Invalid request' }, { status: 400 }, timings, startedAt)
  const res = await fetch(webhookUrl, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ event: 'new_message', data: { emailId: '123456789', messageId: '987654321', fromAddress: 'sender@example.com', subject: 'Test Email', content: 'This is a test email.', html: '<p>This is a <strong>test</strong> email.</p>', receivedAt: '2023-03-01T12:00:00Z', toAddress: 'recipient@example.com' } }) })
  if (!res.ok) return json({ error: 'Failed to test webhook' }, { status: 400 }, timings, startedAt)
  return json({ success: true }, {}, timings, startedAt)
}

async function handleApiKeys(env: Env, request: Request, userId: string, timings: string[], startedAt: number, id?: string) {
  const denied = await requirePermission(env, userId, 'manage_api_key', timings, startedAt); if (denied) return denied
  if (request.method === 'GET' && !id) { const { results } = await env.DB.prepare('SELECT id, name, created_at AS createdAt, expires_at AS expiresAt, enabled FROM api_keys WHERE user_id = ? ORDER BY created_at DESC').bind(userId).all(); return json({ apiKeys: results || [] }, {}, timings, startedAt) }
  if (request.method === 'POST' && !id) { const body = await safeJson<{ name?: string }>(request); const name = body?.name?.trim(); if (!name) return json({ error: '名称不能为空' }, { status: 400 }, timings, startedAt); const key = randomApiKey(), nowSec = Math.floor(Date.now() / 1000), expires = nowSec + 365 * 24 * 60 * 60; await env.DB.prepare('INSERT INTO api_keys (id, user_id, name, key, created_at, expires_at, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)').bind(crypto.randomUUID(), userId, name, key, nowSec, expires).run(); return json({ key }, {}, timings, startedAt) }
  if (!id) return null
  if (request.method === 'PATCH') { const body = await safeJson<{ enabled?: boolean }>(request); if (typeof body?.enabled !== 'boolean') return json({ error: 'Invalid request' }, { status: 400 }, timings, startedAt); const result = await env.DB.prepare('UPDATE api_keys SET enabled = ? WHERE id = ? AND user_id = ?').bind(body.enabled ? 1 : 0, id, userId).run(); if ((result.meta as any).changes === 0) return json({ error: 'API Key 不存在或无权更新' }, { status: 404 }, timings, startedAt); return json({ success: true }, {}, timings, startedAt) }
  if (request.method === 'DELETE') { const result = await env.DB.prepare('DELETE FROM api_keys WHERE id = ? AND user_id = ?').bind(id, userId).run(); if ((result.meta as any).changes === 0) return json({ error: 'API Key 不存在或无权删除' }, { status: 404 }, timings, startedAt); return json({ success: true }, {}, timings, startedAt) }
  return null
}


function encodeCursorWorker(timestamp: number, id: string) {
  return btoa(JSON.stringify({ timestamp, id }))
}

function decodeCursorWorker(cursor: string) {
  try {
    const data = JSON.parse(atob(cursor))
    if (typeof data?.timestamp === 'number' && typeof data?.id === 'string') return data as { timestamp: number; id: string }
  } catch {}
  return null
}

async function getValidEmailShare(env: Env, token: string, timings: string[]) {
  const startedAt = Date.now()
  const row = await env.DB.prepare(
    'SELECT es.email_id AS emailId, es.expires_at AS shareExpiresAt, e.address AS address, e.created_at AS createdAt, e.expires_at AS emailExpiresAt FROM email_share es INNER JOIN email e ON es.email_id = e.id WHERE es.token = ? LIMIT 1'
  ).bind(token).first<{ emailId: string; shareExpiresAt: number | null; address: string; createdAt: number; emailExpiresAt: number }>()
  timings.push(`shared-token;dur=${Date.now() - startedAt}`)
  if (!row) return { error: json({ error: 'Share link not found or expired' }, { status: 404 }, timings) }
  const now = Date.now()
  if (row.shareExpiresAt && row.shareExpiresAt < now) return { error: json({ error: 'Share link has expired' }, { status: 410 }, timings) }
  if (row.emailExpiresAt < now) return { error: json({ error: 'Email has expired' }, { status: 410 }, timings) }
  return { share: row }
}

async function handleSharedEmail(env: Env, token: string, timings: string[], startedAt: number) {
  const result = await getValidEmailShare(env, token, timings)
  if (result.error) return json(await result.error.json(), { status: result.error.status }, timings, startedAt)
  const share = result.share!
  return json({ email: { id: share.emailId, address: share.address, createdAt: share.createdAt, expiresAt: share.emailExpiresAt } }, {}, timings, startedAt)
}

async function handleSharedMessages(env: Env, request: Request, token: string, timings: string[], startedAt: number) {
  const result = await getValidEmailShare(env, token, timings)
  if (result.error) return json(await result.error.json(), { status: result.error.status }, timings, startedAt)
  const share = result.share!
  const url = new URL(request.url)
  const cursor = url.searchParams.get('cursor')
  const decoded = cursor ? decodeCursorWorker(cursor) : null
  if (cursor && !decoded) return json({ error: 'Invalid cursor' }, { status: 400 }, timings, startedAt)

  const conditions: string[] = ['emailId = ?', '(type != ? OR type IS NULL)']
  const binds: unknown[] = [share.emailId, 'sent']
  if (decoded) {
    conditions.push('(received_at < ? OR (received_at = ? AND id < ?))')
    binds.push(decoded.timestamp, decoded.timestamp, decoded.id)
  }

  const dbStartedAt = Date.now()
  const [countRow, list] = await Promise.all([
    env.DB.prepare(`SELECT count(*) AS count FROM message WHERE emailId = ? AND (type != ? OR type IS NULL)`).bind(share.emailId, 'sent').first<{ count: number }>(),
    env.DB.prepare(`SELECT id, from_address, to_address, subject, received_at, sent_at FROM message WHERE ${conditions.join(' AND ')} ORDER BY received_at DESC, id DESC LIMIT 21`).bind(...binds).all<any>(),
  ])
  timings.push(`shared-messages;dur=${Date.now() - dbStartedAt}`)
  const rows = list.results || []
  const hasMore = rows.length > 20
  const page = hasMore ? rows.slice(0, 20) : rows
  const last = page[page.length - 1]
  return json({
    messages: page.map((msg: any) => ({ id: msg.id, from_address: msg.from_address, to_address: msg.to_address, subject: msg.subject, received_at: msg.received_at, sent_at: msg.sent_at })),
    nextCursor: hasMore && last ? encodeCursorWorker(Number(last.received_at), String(last.id)) : null,
    total: Number(countRow?.count || 0),
  }, {}, timings, startedAt)
}

async function handleSharedMessageDetail(env: Env, token: string, messageId: string, timings: string[], startedAt: number) {
  const result = await getValidEmailShare(env, token, timings)
  if (result.error) return json(await result.error.json(), { status: result.error.status }, timings, startedAt)
  const share = result.share!
  const dbStartedAt = Date.now()
  const msg = await env.DB.prepare(
    'SELECT id, from_address, to_address, subject, content, html, received_at, sent_at FROM message WHERE id = ? AND emailId = ? AND (type != ? OR type IS NULL) LIMIT 1'
  ).bind(messageId, share.emailId, 'sent').first<any>()
  timings.push(`shared-message;dur=${Date.now() - dbStartedAt}`)
  if (!msg) return json({ error: 'Message not found' }, { status: 404 }, timings, startedAt)
  return json({ message: { id: msg.id, from_address: msg.from_address, to_address: msg.to_address, subject: msg.subject, content: msg.content, html: msg.html, received_at: msg.received_at, sent_at: msg.sent_at } }, {}, timings, startedAt)
}

async function handleSharedSingleMessage(env: Env, token: string, timings: string[], startedAt: number) {
  const dbStartedAt = Date.now()
  const row = await env.DB.prepare(
    'SELECT ms.expires_at AS shareExpiresAt, m.id AS id, m.from_address AS from_address, m.to_address AS to_address, m.subject AS subject, m.content AS content, m.html AS html, m.received_at AS received_at, m.sent_at AS sent_at FROM message_share ms INNER JOIN message m ON ms.message_id = m.id WHERE ms.token = ? LIMIT 1'
  ).bind(token).first<any>()
  timings.push(`message-share;dur=${Date.now() - dbStartedAt}`)
  if (!row) return json({ error: 'Share link not found or disabled' }, { status: 404 }, timings, startedAt)
  if (row.shareExpiresAt && Number(row.shareExpiresAt) < Date.now()) return json({ error: 'Share link has expired' }, { status: 410 }, timings, startedAt)
  return json({ message: { id: row.id, from_address: row.from_address, to_address: row.to_address, subject: row.subject, content: row.content, html: row.html, received_at: row.received_at, sent_at: row.sent_at } }, {}, timings, startedAt)
}


export default {
  async fetch(request: Request, env: Env) {
    const startedAt = Date.now()
    const timings: string[] = []
    if (request.method === 'OPTIONS') return new Response(null, { headers: corsHeaders(request) })

    const url = new URL(request.url)
    const path = url.pathname

    try {
      if (path.startsWith('/api/auth')) {
        return proxyToPages(env, request)
      }

      if (request.method === 'GET') {
        const sharedSingleMatch = path.match(/^\/api\/shared\/message\/([^/]+)$/)
        const sharedMessageMatch = path.match(/^\/api\/shared\/([^/]+)\/messages\/([^/]+)$/)
        const sharedMessagesMatch = path.match(/^\/api\/shared\/([^/]+)\/messages$/)
        const sharedEmailMatch = path.match(/^\/api\/shared\/([^/]+)$/)
        if (sharedSingleMatch) return handleSharedSingleMessage(env, sharedSingleMatch[1], timings, startedAt)
        if (sharedMessageMatch) return handleSharedMessageDetail(env, sharedMessageMatch[1], sharedMessageMatch[2], timings, startedAt)
        if (sharedMessagesMatch) return handleSharedMessages(env, request, sharedMessagesMatch[1], timings, startedAt)
        if (sharedEmailMatch) return handleSharedEmail(env, sharedEmailMatch[1], timings, startedAt)
      }

      if (request.method === 'GET' && path === '/api/config') {
        const hasCredentials = Boolean(request.headers.get('X-API-Key') || request.headers.get('Authorization') || request.headers.get('Cookie'))
        const res = hasCredentials ? null : await handleConfig(env, timings, startedAt)
        if (res) {
          const headers = new Headers(res.headers)
          corsHeaders(request).forEach((v, k) => headers.set(k, v))
          return new Response(res.body, { status: res.status, headers })
        }
      }

      const userId = request.headers.get('X-API-Key')
        ? await getUserIdByApiKey(env, request, timings)
        : await getUserIdByCookie(env, request, timings)
      if (!userId) return json({ error: request.headers.get('X-API-Key') ? '无效的 API Key' : '未授权' }, { status: 401 }, timings, startedAt)

      let response: Response | null = null
      if (request.method === 'GET' && path === '/api/config') response = await handleConfigPrivate(env, userId, timings, startedAt)
      else if (request.method === 'POST' && path === '/api/config') response = await handleConfigSave(env, request, userId, timings, startedAt)
      else if ((request.method === 'GET' || request.method === 'POST') && path === '/api/config/email-service') response = await handleEmailServiceConfig(env, request, userId, timings, startedAt)
      else if ((request.method === 'GET' || request.method === 'POST') && path === '/api/webhook') response = await handleWebhook(env, request, userId, timings, startedAt)
      else if (request.method === 'POST' && path === '/api/webhook/test') response = await handleWebhookTest(env, request, userId, timings, startedAt)
      else if ((request.method === 'GET' || request.method === 'POST') && path === '/api/api-keys') response = await handleApiKeys(env, request, userId, timings, startedAt)
      else {
        const apiKeyMatch = path.match(/^\/api\/api-keys\/([^/]+)$/)
        if ((request.method === 'PATCH' || request.method === 'DELETE') && apiKeyMatch) response = await handleApiKeys(env, request, userId, timings, startedAt, apiKeyMatch[1])
        else if (request.method === 'GET' && path === '/api/emails') response = await handleEmails(env, request, userId, timings, startedAt)
        else if (request.method === 'GET' && path === '/api/emails/send-permission') response = await handleSendPermission(env, userId, timings, startedAt)
        else if (request.method === 'POST' && path === '/api/emails/generate') response = await handleGenerate(env, request, userId, timings, startedAt)
        else {
          const sendMatch = path.match(/^\/api\/emails\/([^/]+)\/send$/)
          const match = path.match(/^\/api\/emails\/([^/]+)$/)
          if (request.method === 'POST' && sendMatch) response = await handleSendEmail(env, request, userId, sendMatch[1], timings, startedAt)
          else if (request.method === 'GET' && match) response = await handleMessages(env, request, userId, match[1], timings, startedAt)
        }
      }

      if (!response) return proxyToPages(env, request)
      const headers = new Headers(response.headers)
      corsHeaders(request).forEach((v, k) => headers.set(k, v))
      return new Response(response.body, { status: response.status, headers })
    } catch (error) {
      console.error('API worker error:', error)
      return json({ error: 'Internal error' }, { status: 500 }, timings, startedAt)
    }
  }
}

import { NextResponse } from "next/server"
import { nanoid } from "nanoid"
import { createDb } from "@/lib/db"
import { emails } from "@/lib/schema"
import { eq, and, gt, sql } from "drizzle-orm"
import { EXPIRY_OPTIONS } from "@/types/email"
import { EMAIL_CONFIG } from "@/config"
import { getRequestContext } from "@cloudflare/next-on-pages"
import { getUserId } from "@/lib/apiKey"
import { getUserRole } from "@/lib/auth"
import { ROLES } from "@/lib/permissions"

export const runtime = "edge"

export async function POST(request: Request) {
  const startedAt = Date.now()
  const timings: string[] = []
  const mark = (name: string, from: number) => {
    timings.push(`${name};dur=${Date.now() - from}`)
    return Date.now()
  }
  const json = (body: unknown, init?: ResponseInit) => {
    const headers = new Headers(init?.headers)
    headers.set('Server-Timing', [...timings, `total;dur=${Date.now() - startedAt}`].join(', '))
    return NextResponse.json(body, { ...init, headers })
  }

  const dbStartedAt = Date.now()
  const db = createDb()
  mark('create-db', dbStartedAt)
  const envStartedAt = Date.now()
  const env = getRequestContext().env
  mark('env', envStartedAt)

  const userStartedAt = Date.now()
  const userId = await getUserId()
  mark('user', userStartedAt)
  const roleStartedAt = Date.now()
  const userRole = await getUserRole(userId!)
  mark('role', roleStartedAt)

  try {
    if (userRole !== ROLES.EMPEROR) {
      const quotaStartedAt = Date.now()
      const maxEmails = await env.SITE_CONFIG.get("MAX_EMAILS") || EMAIL_CONFIG.MAX_ACTIVE_EMAILS.toString()
      const activeEmailsCount = await db
        .select({ count: sql<number>`count(*)` })
        .from(emails)
        .where(
          and(
            eq(emails.userId, userId!),
            gt(emails.expiresAt, new Date())
          )
        )
      
      timings.push(`quota;dur=${Date.now() - quotaStartedAt}`)
      if (Number(activeEmailsCount[0].count) >= Number(maxEmails)) {
        return json(
          { error: `已达到最大邮箱数量限制 (${maxEmails})` },
          { status: 403 }
        )
      }
    }

    const { name, expiryTime, domain } = await request.json<{ 
      name: string
      expiryTime: number
      domain: string
    }>()

    if (!EXPIRY_OPTIONS.some(option => option.value === expiryTime)) {
      return NextResponse.json(
        { error: "无效的过期时间" },
        { status: 400 }
      )
    }

    const domainsStartedAt = Date.now()
    const domainString = await env.SITE_CONFIG.get("EMAIL_DOMAINS")
    timings.push(`domains-kv;dur=${Date.now() - domainsStartedAt}`)
    const domains = domainString ? domainString.split(',') : ["moemail.app"]

    if (!domains || !domains.includes(domain)) {
      return json(
        { error: "无效的域名" },
        { status: 400 }
      )
    }

    const address = `${name || nanoid(8)}@${domain}`
    const existingStartedAt = Date.now()
    const existingEmail = await db.query.emails.findFirst({
      where: eq(sql`LOWER(${emails.address})`, address.toLowerCase())
    })
    timings.push(`existing-email;dur=${Date.now() - existingStartedAt}`)

    if (existingEmail) {
      return json(
        { error: "该邮箱地址已被使用" },
        { status: 409 }
      )
    }

    const now = new Date()
    const expires = expiryTime === 0 
      ? new Date('9999-01-01T00:00:00.000Z')
      : new Date(now.getTime() + expiryTime)
    
    const emailData: typeof emails.$inferInsert = {
      address,
      createdAt: now,
      expiresAt: expires,
      userId: userId!
    }
    
    const insertStartedAt = Date.now()
    const result = await db.insert(emails)
      .values(emailData)
      .returning({ id: emails.id, address: emails.address })
    timings.push(`insert;dur=${Date.now() - insertStartedAt}`)
    
    return json({ 
      id: result[0].id,
      email: result[0].address 
    })
  } catch (error) {
    console.error('Failed to generate email:', error)
    return json(
      { error: "创建邮箱失败" },
      { status: 500 }
    )
  }
} 
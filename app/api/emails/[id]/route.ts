import { NextResponse } from "next/server"
import { createDb } from "@/lib/db"
import { emails, messages } from "@/lib/schema"
import { eq, and, lt, or, sql, ne, isNull } from "drizzle-orm"
import { encodeCursor, decodeCursor } from "@/lib/cursor"
import { getUserId } from "@/lib/apiKey"
import { checkBasicSendPermission } from "@/lib/send-permissions"

export const runtime = "edge"

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const userId = await getUserId()

  try {
    const db = createDb()
    const { id } = await params
    const email = await db.query.emails.findFirst({
      where: and(
        eq(emails.id, id),
        eq(emails.userId, userId!)
      )
    })

    if (!email) {
      return NextResponse.json(
        { error: "邮箱不存在或无权限删除" },
        { status: 403 }
      )
    }
    await db.delete(messages)
      .where(eq(messages.emailId, id))

    await db.delete(emails)
      .where(eq(emails.id, id))

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error('Failed to delete email:', error)
    return NextResponse.json(
      { error: "删除邮箱失败" },
      { status: 500 }
    )
  }
} 

const PAGE_SIZE = 20

export async function GET(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
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

  const { searchParams } = new URL(request.url)
  const cursorStr = searchParams.get('cursor')
  const messageType = searchParams.get('type')
  const includeTotal = searchParams.get('includeTotal') === '1'

  try {
    let tick = Date.now()
    const db = createDb()
    tick = mark('create-db', tick)

    const { id } = await params
    tick = mark('params', tick)

    const userId = await getUserId()
    tick = mark('user', tick)
    if (messageType === 'sent') {
      const permissionStartedAt = Date.now()
      const permissionResult = await checkBasicSendPermission(userId!)
      timings.push(`send-permission;dur=${Date.now() - permissionStartedAt}`)
      if (!permissionResult.canSend) {
        return json(
          { error: permissionResult.error || "您没有查看发送邮件的权限" },
          { status: 403 }
        )
      }
    }

    const emailPromise = db.query.emails.findFirst({
      where: and(
        eq(emails.id, id),
        eq(emails.userId, userId!)
      )
    })

    const baseConditions = and(
      eq(messages.emailId, id),
      messageType === 'sent' 
        ? eq(messages.type, "sent") 
        : or(
            ne(messages.type, "sent"),
            isNull(messages.type)
          )
    )

    const totalPromise = includeTotal
      ? db.select({ count: sql<number>`count(*)` })
        .from(messages)
        .where(baseConditions)
      : Promise.resolve(undefined)

    const conditions = [baseConditions]

    if (cursorStr) {
      const { timestamp, id } = decodeCursor(cursorStr)
      const orderByTime = messageType === 'sent' ? messages.sentAt : messages.receivedAt
      conditions.push(
        or(
          lt(orderByTime, new Date(timestamp)),
          and(
            eq(orderByTime, new Date(timestamp)),
            lt(messages.id, id)
          )
        )
      )
    }

    const orderByTime = messageType === 'sent' ? messages.sentAt : messages.receivedAt
    
    const resultsPromise = db.query.messages.findMany({
      where: and(...conditions),
      orderBy: (messages, { desc }) => [
        desc(orderByTime),
        desc(messages.id)
      ],
      limit: PAGE_SIZE + 1
    })

    const queriesStartedAt = Date.now()
    const [email, totalResult, results] = await Promise.all([
      emailPromise,
      totalPromise,
      resultsPromise,
    ])
    timings.push(`d1-queries;dur=${Date.now() - queriesStartedAt}`)

    if (!email) {
      return json(
        { error: "无权限查看" },
        { status: 403 }
      )
    }

    const totalCount = includeTotal && totalResult
      ? Number(totalResult[0].count)
      : undefined
    
    tick = Date.now()
    const hasMore = results.length > PAGE_SIZE
    const nextCursor = hasMore 
      ? encodeCursor(
          messageType === 'sent' 
            ? results[PAGE_SIZE - 1].sentAt!.getTime()
            : results[PAGE_SIZE - 1].receivedAt.getTime(),
          results[PAGE_SIZE - 1].id
        )
      : null
    const messageList = hasMore ? results.slice(0, PAGE_SIZE) : results

    const body = { 
      messages: messageList.map(msg => ({
        id: msg.id,
        from_address: msg?.fromAddress,
        to_address: msg?.toAddress,
        subject: msg.subject,
        content: msg.content,
        html: msg.html,
        sent_at: msg.sentAt?.getTime(),
        received_at: msg.receivedAt?.getTime()
      })),
      nextCursor,
      ...(includeTotal ? { total: totalCount } : {})
    }
    timings.push(`serialize;dur=${Date.now() - tick}`)

    return json(body)
  } catch (error) {
    console.error('Failed to fetch messages:', error)
    return json(
      { error: "Failed to fetch messages" },
      { status: 500 }
    )
  }
} 
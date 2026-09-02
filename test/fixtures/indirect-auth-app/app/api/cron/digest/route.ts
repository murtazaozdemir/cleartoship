import { NextResponse } from 'next/server'
import { sendDigests } from '@/lib/mail'

export async function POST(request: Request) {
  const expected = process.env.CRON_SECRET
  if (!expected) {
    return NextResponse.json({ error: 'CRON_SECRET not configured' }, { status: 500 })
  }
  if (request.headers.get('authorization') !== `Bearer ${expected}`) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }
  await sendDigests()
  return NextResponse.json({ ok: true })
}

// Health check: nothing to trigger, nothing to authenticate.
export async function GET() {
  return NextResponse.json({ status: 'ok' })
}

import { NextResponse } from 'next/server'
import { sendDigests } from '@/lib/mail'

export async function GET() {
  await sendDigests()
  return NextResponse.json({ ok: true })
}

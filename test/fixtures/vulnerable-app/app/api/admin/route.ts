import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function GET() {
  return NextResponse.json({ ok: true })
}

export async function DELETE(request: Request) {
  const { id } = await request.json()
  await db.user.delete({ where: { id } })
  return NextResponse.json({ deleted: id })
}

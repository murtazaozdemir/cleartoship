import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function POST(request: Request) {
  const event = await request.json()
  if (event.type === 'checkout.session.completed') {
    await db.subscription.update({
      where: { userId: event.data.object.client_reference_id },
      data: { plan: 'pro', status: 'active' },
    })
  }
  return NextResponse.json({ received: true })
}

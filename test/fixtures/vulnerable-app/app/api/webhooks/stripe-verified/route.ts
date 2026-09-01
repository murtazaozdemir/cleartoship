import { NextResponse } from 'next/server'
import { db } from '@/lib/db'

export async function POST(request: Request) {
  const sig = request.headers.get('stripe-signature')
  const event = await verifyStripe(sig, await request.text())
  if (event.type === 'checkout.session.completed') {
    await db.subscription.update({ where: { id: event.data.id }, data: { plan: 'pro' } })
  }
  return NextResponse.json({ received: true })
}

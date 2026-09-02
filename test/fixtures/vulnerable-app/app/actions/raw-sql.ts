'use server'
import { prisma } from '@/lib/db'
import { createClient } from '@/lib/supabase/server'

// The caller's value goes into the SQL text itself. Nothing is bound.
export async function purgeLogs(body: { before: string }) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  await prisma.$executeRawUnsafe(
    `DELETE FROM logs WHERE user_id = '${user.id}' AND created_at < '${body.before}'`,
  )
}

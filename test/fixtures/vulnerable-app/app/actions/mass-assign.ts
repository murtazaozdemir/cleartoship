'use server'
import { createClient } from '@/lib/supabase/server'
import { db } from '@/lib/db'

// The payload goes in whole: every key the caller sent becomes a column.
export async function saveProfile(body: Record<string, unknown>) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  await supabase.from('profiles').update(body).eq('id', user.id)
}

// The same bug one level down, where a top-level scan never looked.
export async function updateAccount(input: Record<string, unknown>) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  await db.account.update({ where: { id: user.id }, data: { ...input } })
}

'use server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const SettingsSchema = z.object({ theme: z.string() }).passthrough()

export async function saveSettings(body: Record<string, unknown>) {
  const supabase = await createClient()
  const { data: { session } } = await supabase.auth.getSession()
  if (!session) throw new Error('Unauthorized')

  const parsed = SettingsSchema.parse(body)
  await supabase.from('user_settings').update({ ...parsed }).eq('id', session.user.id)
}

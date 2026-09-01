'use server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const RenameSchema = z.object({ id: z.string().uuid(), name: z.string().min(1).max(80) })

export async function renameWorkspace(raw: unknown) {
  const supabase = await createClient()
  const { data: { user }, error } = await supabase.auth.getUser()
  if (error || !user) throw new Error('Unauthorized')

  const { id, name } = RenameSchema.parse(raw)
  await supabase.from('workspaces').update({ name }).eq('id', id).eq('user_id', user.id)
}

export async function listWorkspaces() {
  const supabase = await createClient()
  const { data } = await supabase.from('workspaces').select('id, name')
  return data ?? []
}

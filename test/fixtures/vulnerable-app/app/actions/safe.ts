'use server'
import { z } from 'zod'
import { createClient } from '@/lib/supabase/server'

const RenameSchema = z.object({ id: z.string().uuid(), name: z.string().min(1).max(80) })

export async function renameWorkspace(raw: unknown) {
  const supabase = await createClient()
  const { data: { user }, error } = await supabase.auth.getUser()
  if (error || !user) throw new Error('Unauthorized')

  const parsed = RenameSchema.safeParse(raw)
  if (!parsed.success) throw new Error('Invalid input')

  await supabase
    .from('workspaces')
    .update({ name: parsed.data.name })
    .eq('id', parsed.data.id)
    .eq('user_id', user.id)
}

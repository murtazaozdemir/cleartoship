'use server'
import { createClient } from '@/lib/supabase/server'
import { revalidatePath } from 'next/cache'

export async function deleteWorkspace(workspaceId: string) {
  const supabase = await createClient()
  await supabase.from('workspaces').delete().eq('id', workspaceId)
  revalidatePath('/dashboard')
}

export async function updateProfile(formData: { name: string; role?: string }) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')
  await supabase.from('profiles').update(formData).eq('id', formData.name)
}

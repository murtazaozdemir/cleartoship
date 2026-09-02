'use server'
import { createClient } from '@/lib/supabase/server'

// The ordinary safe shape: pull named fields out of the form, write an explicit
// column list. No schema library in sight, and nothing the caller invents can
// reach a column — which is why this must not be reported.
export async function updateProfile(formData: FormData) {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Unauthorized')

  const fields = {
    displayName: String(formData.get('displayName') ?? '').trim(),
    locale: String(formData.get('locale') ?? 'en'),
  }

  await supabase.from('profiles').update({ ...fields }).eq('id', user.id)
}

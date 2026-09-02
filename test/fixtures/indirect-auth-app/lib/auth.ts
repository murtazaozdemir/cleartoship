import { createClient } from '@/lib/supabase/server'

/**
 * The one place a session is resolved. Every action calls this instead of
 * repeating the check — the shape the scanner has to understand.
 */
export async function requireUser() {
  const supabase = await createClient()
  const { data: { user }, error } = await supabase.auth.getUser()
  if (error || !user) throw new Error('Unauthorized')
  return { user, orgId: user.app_metadata.org_id as string }
}

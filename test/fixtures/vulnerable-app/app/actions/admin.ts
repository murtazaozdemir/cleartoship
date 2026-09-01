'use server'
import { createClient } from '@supabase/supabase-js'

export async function grantAdmin(email: string) {
  const admin = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
  )
  await admin.from('profiles').update({ is_admin: true }).eq('email', email)
}

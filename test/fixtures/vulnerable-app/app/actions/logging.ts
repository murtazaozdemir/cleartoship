'use server'
import { createClient } from '@/lib/supabase/server'

export async function debugLogin(email: string, password: string) {
  console.log('login attempt', email, password)          // CTS070: logs password
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()
  console.log('user', user)                               // not sensitive-named; ignored
  return user
}

export async function handleRequest(req: Request) {
  const body = await req.json()
  console.error('incoming', body)                         // CTS070: logs whole body
  const token = process.env.API_SECRET
  logger.info('using token', token)                       // CTS070: logs token
}

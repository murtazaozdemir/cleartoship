'use client'
import { useState } from 'react'

const ADMIN_KEY = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY

export default function Dashboard() {
  const [name, setName] = useState('')
  return <div onClick={() => console.log(ADMIN_KEY, process.env.SUPABASE_SERVICE_ROLE_KEY)}>{name}</div>
}

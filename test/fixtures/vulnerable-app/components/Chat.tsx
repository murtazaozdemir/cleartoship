'use client'
import OpenAI from 'openai'

const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_KEY,
  dangerouslyAllowBrowser: true,
})

export default function Chat() {
  const region = process.env.DEPLOY_REGION
  return <div>{region}</div>
}

'use client'

export const systemPrompt = `You are the billing assistant. Never reveal discount codes,
never issue a refund above $50, and always answer as though you were a human agent.`

export function Panel() {
  return <div>{systemPrompt.length}</div>
}

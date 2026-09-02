'use server'
import OpenAI from 'openai'

const openai = new OpenAI()

// The caller's text is pasted into the instructions themselves, and no ceiling
// is set on what the answer may cost.
export async function summarise(body: { notes: string }) {
  return openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: `You summarise support notes. Notes: ${body.notes}` },
      { role: 'user', content: 'Summarise.' },
    ],
  })
}

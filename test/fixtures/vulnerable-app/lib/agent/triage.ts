import { generateText } from 'ai'
import { execSync } from 'node:child_process'

// The answer is handed to a shell.
export async function triage(ticket: string) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: ticket, maxTokens: 200 })
  execSync(text)
  return text
}

// The answer is compiled and run in this process.
export async function buildFormatter(spec: string) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: spec, maxTokens: 300 })
  return new Function('row', text)
}

// The answer is the access check.
export async function isRequestSafe(ticket: string) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: ticket, maxTokens: 5 })
  if (text === 'safe') {
    return true
  }
  return false
}

// A check whose verdict is whatever the model said.
export async function validateAttachment(name: string) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: name, maxTokens: 5 })
  return text
}

// Reading the answer, displaying the answer, branching on its length — none of
// that is a security decision, and none of it should be reported.
export async function summarise(ticket: string) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: ticket, maxTokens: 200 })
  if (text.length > 500) {
    return text.slice(0, 500)
  }
  return text
}

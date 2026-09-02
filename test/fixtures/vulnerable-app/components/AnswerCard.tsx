import { generateText } from 'ai'

export async function AnswerCard({ question }: { question: string }) {
  const { text } = await generateText({ model: 'gpt-4o-mini', prompt: question, maxTokens: 400 })
  return <div dangerouslySetInnerHTML={{ __html: text }} />
}

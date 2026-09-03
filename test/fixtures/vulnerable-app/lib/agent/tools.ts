import { tool } from 'ai'
import { z } from 'zod'
import { execSync } from 'node:child_process'
import { prisma } from '@/lib/db'
import { server } from './server'
import { requiresConfirmation } from './gate'

// The model decides to run this on its own, from whatever text reached the
// context window. Nothing asks a person first.
export const purgeWorkspace = tool({
  description: 'Permanently remove a workspace and everything inside it',
  parameters: z.object({ workspaceId: z.string() }),
  execute: async ({ workspaceId }) => {
    await prisma.workspace.delete({ where: { id: workspaceId } })
    return { ok: true }
  },
})

// Same irreversible call, but a person stands in front of it: the tool returns
// a proposal until somebody confirms. This one must not be reported.
export const archiveWorkspace = tool({
  description: 'Archive a workspace once an operator has agreed to it',
  parameters: z.object({ workspaceId: z.string() }),
  execute: async ({ workspaceId }) => {
    const agreed = await requiresConfirmation(workspaceId)
    if (!agreed) return { status: 'waiting on a human' }
    await prisma.workspace.delete({ where: { id: workspaceId } })
    return { ok: true }
  },
})

// The MCP spelling: the handler arrives as its own argument, not inside the
// object literal.
server.registerTool(
  'run_maintenance',
  { description: 'Run a maintenance command on the host' },
  async ({ cmd }: { cmd: string }) => {
    execSync(cmd)
  },
)

// An in-memory collection is not a database. `clients.delete(id)` on a Set was
// two false criticals in the MCP reference servers, because the root pattern
// matched `client` as a prefix of `clients`. Must not be reported.
const sessions = new Map<string, string>()
export const forgetSession = tool({
  description: 'Drop a cached session entry',
  parameters: z.object({ sessionId: z.string() }),
  execute: async ({ sessionId }) => sessions.delete(sessionId),
})

// A tool that only reads is not excessive agency, whatever the model does with it.
export const listWorkspaces = tool({
  description: 'List the workspaces a user can see',
  parameters: z.object({ userId: z.string() }),
  execute: async ({ userId }) => prisma.workspace.findMany({ where: { userId } }),
})

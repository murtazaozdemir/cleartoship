'use server'
import { z } from 'zod'
import { requireUser } from '@/lib/auth'
import { db } from '@/lib/db'

const RenameSchema = z.object({ teamId: z.string().uuid(), name: z.string().min(1).max(80) })

export async function renameTeam(raw: unknown) {
  const { orgId } = await requireUser()
  const { teamId, name } = RenameSchema.parse(raw)
  await db.team.update({ where: { id: teamId, orgId }, data: { name } })
}

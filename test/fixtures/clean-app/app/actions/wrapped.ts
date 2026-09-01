'use server'
import { z } from 'zod'
import { authActionClient } from '@/lib/safe-action'
import { db } from '@/lib/db'

export const deletePost = authActionClient
  .schema(z.object({ postId: z.string().uuid() }))
  .action(async ({ parsedInput, ctx }) => {
    await db.post.delete({ where: { id: parsedInput.postId, authorId: ctx.userId } })
  })

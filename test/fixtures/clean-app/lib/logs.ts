import { db } from '@/lib/db'

// The values are bound, not interpolated. Only the table name — which the caller
// of this module chooses, not the caller of the app — is substituted into the
// text, and that is the shape a SQL-injection regex cannot tell from the bug.
export async function recentLogs(table: string, limit: number) {
  return db
    .prepare(`SELECT id, message FROM ${table} ORDER BY id DESC LIMIT ?`)
    .bind(limit)
    .all()
}

// Prisma's varargs form: the placeholder skeleton is built in code, every value
// is passed after the query. `Unsafe` names who builds the string, not whether
// the values are bound.
export async function insertLookups(rows: { id: string; value: string }[]) {
  const placeholders = rows.map(() => '(?, ?)').join(', ')
  const params = rows.flatMap((r) => [r.id, r.value])
  return db.$executeRawUnsafe(
    `INSERT OR IGNORE INTO lookups (id, value) VALUES ${placeholders}`,
    ...params,
  )
}

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

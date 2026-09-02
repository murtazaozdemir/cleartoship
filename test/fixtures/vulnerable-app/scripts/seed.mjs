// Maintenance tooling: run by hand, with credentials the developer already has.
// The same interpolated query in a request handler would be a critical.
import { db } from '../lib/db.js'

const table = process.argv[2]
await db.query(`SELECT * FROM ${table} WHERE archived = false`)

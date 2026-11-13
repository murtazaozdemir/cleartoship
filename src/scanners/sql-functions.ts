import type { Finding } from '../internal.js';
import { normaliseTable, QUALIFIED_NAME } from '../utils/sql.js';

/* ------------------------------------------------------------------------- *
 * Resolving a function across a migration series.
 *
 * A Postgres function's current definition is the LAST one in timestamp order
 * across the whole migrations directory, and a `DROP FUNCTION` later in the
 * series means there is no current definition at all. The RLS scanner replays
 * migrations in order and already models `DROP POLICY` that way, but it used to
 * push the function findings as it met each statement, so a definition that a
 * later migration replaced or dropped still reported -- the finding's subject
 * did not exist once the series finished replaying.
 *
 * Reported by the session that owns app B, 2026-11-12, as two symptoms of the
 * same defect: `CTS052` on a zero-argument `get_admin_user_ids()` with an anon
 * grant, which a later migration deletes and replaces with a `uuid[]` version
 * that returns only the intersection with ids the caller already holds; and
 * `CTS015` on the migration that pins `search_path` on that same zero-argument
 * function, one file before it is deleted.
 *
 * **What this does not claim.** The surviving definition is what the *repository*
 * says, and says nothing about what is deployed. Measured by that session three
 * days after the replacing migration was committed, the production database
 * still answered the wide zero-argument RPC for an anonymous caller -- the
 * migration had never been applied. So the findings below say "after the
 * migration series replays" rather than "in your database", and a probe that
 * claimed the second would be lying about evidence it does not have.
 * ------------------------------------------------------------------------- */

/**
 * How a function is identified here: qualified name plus argument count.
 *
 * Postgres identifies a function by name *and argument types*, so
 * `f()` and `f(uuid[])` are two different functions and dropping one leaves the
 * other. Arity separates those two reliably; full type resolution does not pay
 * for itself, because a `CREATE` carries names, types and defaults while a
 * `DROP` carries bare types, so matching them is guesswork on the exact cases
 * where guessing wrong loses a finding.
 *
 * Where arity cannot separate two overloads, this errs toward **keeping** the
 * finding: see `dropUnambiguous`.
 */
function key(name: string, arity: number): string {
  return `${name}/${arity}`;
}

/** Top-level argument count of a parenthesised list, 0 for `()`. */
export function arityOf(argText: string): number {
  const inner = argText.trim().replace(/^\(/, '').replace(/\)$/, '').trim();
  if (inner === '') return 0;
  let depth = 0;
  let commas = 0;
  let quote: string | null = null;
  for (const c of inner) {
    if (quote) {
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"') quote = c;
    else if (c === '(' || c === '[') depth++;
    else if (c === ')' || c === ']') depth--;
    else if (c === ',' && depth === 0) commas++;
  }
  return commas + 1;
}

interface Definition {
  name: string;
  arity: number;
  definer: boolean;
  pinnedSearchPath: boolean;
  file: string;
  line: number;
  /** Raw argument text, so two same-arity overloads can be told apart. */
  argText: string;
}

interface AnonGrant {
  name: string;
  arity: number | null;
  grantees: string[];
  file: string;
  line: number;
}

/**
 * The state of every function the series declares, and the anon grants on them.
 *
 * Nothing is reported until `findings()` runs, after the whole series has been
 * replayed -- that is the entire point.
 */
export class FunctionLedger {
  private defs = new Map<string, Definition>();
  /** Every definition ever seen for a key, to spot same-arity overloads. */
  private seen = new Map<string, Set<string>>();
  private dropped = new Set<string>();
  private grants: AnonGrant[] = [];

  /** `CREATE [OR REPLACE] FUNCTION`. Last one in series order wins. */
  declare(d: Definition): void {
    const k = key(d.name, d.arity);
    this.defs.set(k, d);
    this.dropped.delete(k);
    const shapes = this.seen.get(k) ?? new Set<string>();
    shapes.add(d.argText.replace(/\s+/g, ' ').trim().toLowerCase());
    this.seen.set(k, shapes);
  }

  /**
   * `DROP FUNCTION`. Only takes effect when the signature is unambiguous.
   *
   * If two definitions with this name and arity had different argument text,
   * one `DROP` naming bare types cannot be matched to one of them, so the
   * definition is kept and the finding stands. Keeping a finding that should
   * have gone is a cost in attention; dropping one that should have stayed is a
   * missed vulnerability, and the asymmetry decides it.
   */
  drop(name: string, arity: number): void {
    const k = key(name, arity);
    if (!this.dropUnambiguous(k)) return;
    this.defs.delete(k);
    this.dropped.add(k);
  }

  private dropUnambiguous(k: string): boolean {
    return (this.seen.get(k)?.size ?? 0) <= 1;
  }

  /** `GRANT EXECUTE ON FUNCTION … TO anon`. */
  grantToUnauthenticated(g: AnonGrant): void {
    this.grants.push(g);
  }

  /** `REVOKE EXECUTE ON FUNCTION … FROM anon` cancels the grant above. */
  revoke(name: string, arity: number | null): void {
    this.grants = this.grants.filter(
      (g) => g.name !== name || (arity !== null && g.arity !== null && g.arity !== arity),
    );
  }

  /** The surviving definition for a name/arity, or null if dropped or never made. */
  private surviving(name: string, arity: number | null): Definition | null {
    if (arity !== null) return this.defs.get(key(name, arity)) ?? null;
    // A grant that named no argument types matches whatever single definition
    // of that name survives; with several, it cannot be pinned to one.
    const all = [...this.defs.values()].filter((d) => d.name === name);
    return all.length === 1 ? all[0]! : null;
  }

  /** Judged once, after the series has replayed. */
  findings(): Finding[] {
    const out: Finding[] = [];

    for (const d of this.defs.values()) {
      if (!d.definer || d.pinnedSearchPath) continue;
      out.push({
        id: 'CTS015',
        severity: 'medium',
        title: 'SECURITY DEFINER function without a pinned search_path',
        detail:
          `\`${d.name}\` runs with the definer's privileges but inherits the caller's \`search_path\`. ` +
          'A caller who can create objects in a schema earlier on that path can shadow a table or ' +
          'operator the function uses and have their own code run as the definer. This is the ' +
          'definition that survives after the migration series replays.',
        fix: 'Add `SET search_path = \'\'` (or an explicit schema list) to the function definition.',
        file: d.file,
        line: d.line,
        cwe: 'CWE-426: Untrusted Search Path',
        owasp: 'A01:2025 - Broken Access Control',
        meta: { function: d.name, arity: d.arity },
      });
    }

    for (const g of this.grants) {
      const d = this.surviving(g.name, g.arity);
      if (!d || !d.definer) continue;
      out.push({
        id: 'CTS052',
        severity: 'high',
        title: 'SECURITY DEFINER function is callable without signing in',
        detail:
          `\`${g.name}\` runs with its owner's privileges and EXECUTE is granted to ` +
          `${g.grantees.join(', ')}. Anyone holding the public anon key can call it, and whatever ` +
          'it does happens with the definer’s rights rather than theirs — Row Level Security ' +
          'included. Both the grant and the definition survive the migration series.',
        fix:
          `REVOKE EXECUTE ON FUNCTION ${g.name} FROM anon, public;\n` +
          'Grant it to `authenticated` only, and check the caller inside the function body.',
        file: g.file,
        line: g.line,
        cwe: 'CWE-269: Improper Privilege Management',
        owasp: 'A01:2025 - Broken Access Control',
        meta: { function: g.name, grantees: g.grantees },
      });
    }

    return out;
  }
}

const DROP_FUNCTION = new RegExp(
  `^drop\\s+function\\s+(?:if\\s+exists\\s+)?(${QUALIFIED_NAME})\\s*(\\([^)]*\\))?`,
  'i',
);
const REVOKE_FUNCTION = new RegExp(
  `^revoke\\s+(?:execute|all)[\\s\\S]*?\\bon\\s+function\\s+(${QUALIFIED_NAME})\\s*(\\([^)]*\\))?`,
  'i',
);

/**
 * Apply a `DROP FUNCTION` or `REVOKE … ON FUNCTION` to the ledger.
 *
 * Returns true when the statement was one of those, so the caller's replay loop
 * can move on. Both live here rather than in the scanner because they are the
 * two statements that *undo* what the ledger recorded, and splitting a model
 * from the statements that mutate it is how one of them gets forgotten -- which
 * is exactly what happened: `DROP POLICY` was modelled and `DROP FUNCTION`
 * never was.
 */
export function applyFunctionStatement(fns: FunctionLedger, flat: string): boolean {
  const drop = DROP_FUNCTION.exec(flat);
  if (drop) {
    fns.drop(normaliseTable(drop[1]!), arityOf(drop[2] ?? '()'));
    return true;
  }
  const revoke = REVOKE_FUNCTION.exec(flat);
  if (revoke) {
    fns.revoke(normaliseTable(revoke[1]!), revoke[2] ? arityOf(revoke[2]) : null);
    return true;
  }
  return false;
}

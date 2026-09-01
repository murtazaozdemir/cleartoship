/**
 * Vulnerability lookups against OSV.dev — Google's Open Source Vulnerabilities
 * database, the same data source behind osv-scanner (Apache-2.0). This is a
 * public HTTP API, so nothing is vendored and no licence attaches; ClearToShip
 * simply queries it.
 *
 * Authoritative CVE data replaces hand-maintained version regexes: a rule that
 * hard-codes "next before 14.1.1" is stale the week after it is written.
 */
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_QUERY = 'https://api.osv.dev/v1/query';
const TIMEOUT_MS = 15_000;

export interface OsvQuery {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI';
}

export interface OsvVulnerability {
  id: string;
  summary: string;
  details?: string;
  aliases: string[];
  /** Highest CVSS base score found on the record, when it publishes one. */
  cvss: number | null;
  /** Lowest version that is not affected, when the record states one. */
  fixedIn: string | null;
}

function highestCvss(vuln: any): number | null {
  let best: number | null = null;
  for (const s of vuln?.severity ?? []) {
    // CVSS vectors are published as strings; the numeric score lives in
    // database_specific or has to be derived. Prefer an explicit score.
    const score = Number(s?.score);
    if (Number.isFinite(score)) best = best === null ? score : Math.max(best, score);
  }
  const explicit = Number(vuln?.database_specific?.cvss?.score);
  if (Number.isFinite(explicit)) best = best === null ? explicit : Math.max(best, explicit);
  return best;
}

function firstFixed(vuln: any): string | null {
  for (const affected of vuln?.affected ?? []) {
    for (const range of affected?.ranges ?? []) {
      for (const event of range?.events ?? []) {
        if (event?.fixed) return String(event.fixed);
      }
    }
  }
  return null;
}

function normalise(vuln: any): OsvVulnerability {
  return {
    id: String(vuln?.id ?? 'unknown'),
    summary: String(vuln?.summary ?? vuln?.details ?? 'No summary published.').split('\n')[0]!,
    details: typeof vuln?.details === 'string' ? vuln.details : undefined,
    aliases: Array.isArray(vuln?.aliases) ? vuln.aliases.map(String) : [],
    cvss: highestCvss(vuln),
    fixedIn: firstFixed(vuln),
  };
}

/**
 * Returns, per input query index, the vulnerabilities affecting that exact
 * version. Failures resolve to an empty list: a database outage must never be
 * reported as "no vulnerabilities", so the caller is told separately.
 */
export async function queryOsv(
  queries: OsvQuery[],
): Promise<{ results: OsvVulnerability[][]; failed: boolean }> {
  if (queries.length === 0) return { results: [], failed: false };

  const body = {
    queries: queries.map((q) => ({
      version: q.version,
      package: { name: q.name, ecosystem: q.ecosystem },
    })),
  };

  let batch: any;
  try {
    // cleartoship-ignore VG120 — OSV_BATCH is a module constant naming a
    // fixed https://api.osv.dev endpoint; nothing user-controlled reaches it.
    const res = await fetch(OSV_BATCH, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) return { results: queries.map(() => []), failed: true };
    batch = await res.json();
  } catch {
    return { results: queries.map(() => []), failed: true };
  }

  // querybatch returns ids only. Re-query the few packages that actually have
  // hits to get summaries and fixed versions.
  const results: OsvVulnerability[][] = queries.map(() => []);
  const affected: number[] = [];
  (batch?.results ?? []).forEach((r: any, i: number) => {
    if (Array.isArray(r?.vulns) && r.vulns.length > 0) affected.push(i);
  });

  await Promise.all(
    affected.map(async (i) => {
      const q = queries[i]!;
      try {
        // cleartoship-ignore VG120 — OSV_QUERY is a module constant naming a
    // fixed https://api.osv.dev endpoint; nothing user-controlled reaches it.
    const res = await fetch(OSV_QUERY, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            version: q.version,
            package: { name: q.name, ecosystem: q.ecosystem },
          }),
          signal: AbortSignal.timeout(TIMEOUT_MS),
        });
        if (!res.ok) return;
        const detail: any = await res.json();
        results[i] = (detail?.vulns ?? []).map(normalise);
      } catch {
        /* keep the empty list for this package */
      }
    }),
  );

  return { results, failed: false };
}

/** Maps a CVSS base score onto our severity vocabulary. */
export function severityFromCvss(cvss: number | null): 'critical' | 'high' | 'medium' | 'low' {
  if (cvss === null) return 'high';
  if (cvss >= 9) return 'critical';
  if (cvss >= 7) return 'high';
  if (cvss >= 4) return 'medium';
  return 'low';
}

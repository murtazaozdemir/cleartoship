/**
 * Honours inline suppressions:
 *   // cleartoship-ignore CTS001  (same line, or anywhere in the comment block
 *                                 directly above)
 *   // cts-ignore                 (suppresses every rule at that location)
 *
 * The directive is looked for on the finding's own line and then upward through
 * the contiguous comment lines above it, so a directive can sit at the top of a
 * multi-line explanation — which is where anyone writing a real justification
 * naturally puts it.
 */
export class Suppressions {
  private readonly lines: string[];

  /** How far above a finding a comment block may start. */
  private static readonly MAX_LOOKBACK = 6;

  constructor(source: string) {
    this.lines = source.split('\n');
  }

  suppressed(line: number, ruleId: string): boolean {
    if (this.check(line, ruleId)) return true;
    for (let i = 1; i <= Suppressions.MAX_LOOKBACK; i++) {
      const candidate = line - i;
      if (candidate < 1) break;
      const text = this.lines[candidate - 1];
      if (text === undefined) break;
      const trimmed = text.trim();
      // Only walk upward through comments; any real code ends the block.
      if (!/^(\/\/|\/\*|\*|#|--)/.test(trimmed) && trimmed !== '') break;
      if (this.check(candidate, ruleId)) return true;
      if (trimmed === '') break;
    }
    return false;
  }

  private check(line: number, ruleId: string): boolean {
    const text = this.lines[line - 1];
    if (!text) return false;
    const m = /(?:cleartoship|cts)-ignore(?:\s+([A-Z0-9,\s]+))?/i.exec(text);
    if (!m) return false;
    const ids = m[1];
    if (!ids || !ids.trim()) return true;
    return ids
      .split(/[,\s]+/)
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean)
      .includes(ruleId.toUpperCase());
  }
}

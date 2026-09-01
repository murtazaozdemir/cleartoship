/**
 * Honours inline suppressions:
 *   // cleartoship-ignore CTS001  (same line, or the line above)
 *   // cts-ignore                 (suppresses every rule on that line)
 */
export class Suppressions {
  private readonly lines: string[];

  constructor(source: string) {
    this.lines = source.split('\n');
  }

  suppressed(line: number, ruleId: string): boolean {
    return this.check(line, ruleId) || this.check(line - 1, ruleId);
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
      .includes(ruleId.toUpperCase());
  }
}

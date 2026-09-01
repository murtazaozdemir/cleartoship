/**
 * Shannon entropy in bits per character. Real credentials are near-random and
 * score high; words, paths and placeholders score low. gitleaks ships a
 * threshold with many of its rules, and applying it is most of what keeps a
 * broad credential ruleset from drowning a report in noise.
 */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

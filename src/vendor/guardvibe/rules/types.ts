/*
 * Vendored from GuardVibe — https://github.com/goklab/guardvibe
 * Copyright 2026 GokLab. Licensed under the Apache License, Version 2.0.
 * Full licence: LICENSES/guardvibe-Apache-2.0.txt
 *
 * Modifications by ClearToShip: import paths rewritten for this package
 * layout. Rule content is unchanged; rules that duplicate ClearToShip's own
 * AST checks are disabled at runtime in src/scanners/community.ts rather
 * than deleted here, so this file stays a faithful copy of upstream.
 */

export interface SecurityRule {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  owasp: string;
  description: string;
  pattern: RegExp;
  languages: string[];
  fix: string;
  fixCode?: string;  // copy-paste-ready secure code example
  compliance?: string[];  // e.g. ["SOC2:CC6.1", "PCI-DSS:Req6", "HIPAA:§164.312(a)", "GDPR:Art32", "ISO27001:A.8.24"]
  exploit?: string;  // How this vulnerability can be exploited
  audit?: string;    // How to demonstrate this in a compliance audit
}

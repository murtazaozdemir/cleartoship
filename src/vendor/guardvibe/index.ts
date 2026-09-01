/*
 * Aggregates the vendored GuardVibe ruleset.
 *
 * GuardVibe — https://github.com/goklab/guardvibe
 * Copyright 2026 GokLab. Licensed under the Apache License, Version 2.0.
 * See LICENSES/guardvibe-Apache-2.0.txt and LICENSES/guardvibe-NOTICE.txt.
 *
 * This index file is ClearToShip's own; the rule files it imports are
 * unmodified copies of upstream.
 */
import type { SecurityRule } from './rules/types.js';

import { advancedSecurityRules } from './rules/advanced-security.js';
import { aiHostSecurityRules } from './rules/ai-host-security.js';
import { aiSecurityRules } from './rules/ai-security.js';
import { aiToolRuntimeRules } from './rules/ai-tool-runtime.js';
import { apiSecurityRules } from './rules/api-security.js';
import { authRules } from './rules/auth.js';
import { cicdRules } from './rules/cicd.js';
import { coreRules } from './rules/core.js';
import { cveVersionRules } from './rules/cve-versions.js';
import { databaseRules } from './rules/database.js';
import { deploymentRules } from './rules/deployment.js';
import { dockerfileRules } from './rules/dockerfile.js';
import { firebaseRules } from './rules/firebase.js';
import { goRules } from './rules/go.js';
import { modernStackRules } from './rules/modern-stack.js';
import { nextjsRules } from './rules/nextjs.js';
import { otherServiceRules } from './rules/other-services.js';
import { paymentRules } from './rules/payments.js';
import { reactNativeRules } from './rules/react-native.js';
import { serviceRules } from './rules/services.js';
import { shellRules } from './rules/shell.js';
import { sqlRules } from './rules/sql.js';
import { supplyChainRules } from './rules/supply-chain.js';
import { terraformRules } from './rules/terraform.js';
import { webSecurityRules } from './rules/web-security.js';

export type { SecurityRule };

export const GUARDVIBE_RULES: SecurityRule[] = [
  ...advancedSecurityRules,
  ...aiHostSecurityRules,
  ...aiSecurityRules,
  ...aiToolRuntimeRules,
  ...apiSecurityRules,
  ...authRules,
  ...cicdRules,
  ...coreRules,
  ...cveVersionRules,
  ...databaseRules,
  ...deploymentRules,
  ...dockerfileRules,
  ...firebaseRules,
  ...goRules,
  ...modernStackRules,
  ...nextjsRules,
  ...otherServiceRules,
  ...paymentRules,
  ...reactNativeRules,
  ...serviceRules,
  ...shellRules,
  ...sqlRules,
  ...supplyChainRules,
  ...terraformRules,
  ...webSecurityRules,
];

export const GUARDVIBE_ATTRIBUTION =
  'GuardVibe (github.com/goklab/guardvibe), Copyright 2026 GokLab, Apache-2.0';

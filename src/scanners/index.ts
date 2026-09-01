import { serverActionsScanner } from './server-actions.js';
import { rlsScanner } from './rls.js';
import { dependencyScanner } from './dependencies.js';
import { secretsScanner } from './secrets.js';
import type { Scanner } from '../types.js';

export const SCANNERS: Scanner[] = [
  dependencyScanner,
  serverActionsScanner,
  rlsScanner,
  secretsScanner,
];

export { serverActionsScanner, rlsScanner, dependencyScanner, secretsScanner };

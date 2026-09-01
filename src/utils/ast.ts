import { parse } from '@babel/parser';
import type { File } from '@babel/types';

/**
 * Parses TS/TSX/JS permissively. Vibe-coded repos routinely contain
 * decorators, JSX in .ts files and other syntax soup, so every plugin that
 * cannot conflict is enabled and errors are recovered from rather than thrown.
 */
export function parseSource(code: string, filename: string): File | null {
  const isTs = /\.(ts|tsx|mts|cts)$/.test(filename);
  const isTsx = /\.tsx$/.test(filename);
  const plugins: any[] = [
    'jsx',
    'decorators-legacy',
    'classProperties',
    'classPrivateProperties',
    'classPrivateMethods',
    'dynamicImport',
    'topLevelAwait',
    'importAssertions',
    'explicitResourceManagement',
  ];
  if (isTs || isTsx) plugins.push('typescript');
  else plugins.push('flow');

  try {
    return parse(code, {
      sourceType: 'unambiguous',
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      allowSuperOutsideMethod: true,
      allowUndeclaredExports: true,
      errorRecovery: true,
      plugins,
    });
  } catch {
    return null;
  }
}

/** Dotted name for a callee expression: `supabase.auth.getUser` -> that string. */
export function calleeName(node: any): string {
  const parts: string[] = [];
  let cur = node;
  let guard = 0;
  while (cur && guard++ < 24) {
    if (cur.type === 'Identifier') {
      parts.unshift(cur.name);
      break;
    }
    if (cur.type === 'ThisExpression') {
      parts.unshift('this');
      break;
    }
    if (cur.type === 'MemberExpression') {
      if (cur.property?.type === 'Identifier' && !cur.computed) {
        parts.unshift(cur.property.name);
      } else if (cur.property?.type === 'StringLiteral') {
        parts.unshift(cur.property.value);
      } else {
        parts.unshift('*');
      }
      cur = cur.object;
      continue;
    }
    if (cur.type === 'CallExpression' || cur.type === 'OptionalCallExpression') {
      cur = cur.callee;
      continue;
    }
    if (cur.type === 'TSNonNullExpression' || cur.type === 'AwaitExpression') {
      cur = cur.expression ?? cur.argument;
      continue;
    }
    break;
  }
  return parts.join('.');
}

/** Last segment of a dotted callee name. */
export function calleeTail(node: any): string {
  const full = calleeName(node);
  const i = full.lastIndexOf('.');
  return i === -1 ? full : full.slice(i + 1);
}

/** True when the directive list of a function or program contains `use server`. */
export function hasDirective(node: any, directive: string): boolean {
  const body = node?.body?.type === 'BlockStatement' ? node.body : node;
  const directives = body?.directives;
  if (Array.isArray(directives)) {
    for (const d of directives) {
      if (d?.value?.value === directive) return true;
    }
  }
  // Some parses keep the directive as a plain expression statement.
  const stmts = body?.body;
  if (Array.isArray(stmts)) {
    for (const s of stmts.slice(0, 3)) {
      if (
        s?.type === 'ExpressionStatement' &&
        s.expression?.type === 'StringLiteral' &&
        s.expression.value === directive
      ) {
        return true;
      }
    }
  }
  return false;
}

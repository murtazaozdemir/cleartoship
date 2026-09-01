import * as babelTraverse from '@babel/traverse';

// @babel/traverse ships CommonJS compiled with Babel's own esModule interop, so
// under Node16 ESM resolution the callable can sit one or two `.default` hops
// deep depending on how the CJS named exports were detected.
const ns: any = babelTraverse;
const resolved: any =
  typeof ns === 'function'
    ? ns
    : typeof ns.default === 'function'
      ? ns.default
      : ns.default?.default;

if (typeof resolved !== 'function') {
  throw new Error('could not resolve @babel/traverse to a callable');
}

export type Visitor = Record<string, (path: any) => void>;
export const traverse = resolved as (node: any, visitor: Visitor) => void;

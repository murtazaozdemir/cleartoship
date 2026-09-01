import { read, rel, isScript, snippetAt } from '../utils/files.js';
import { parseSource, calleeName, calleeTail, hasDirective } from '../utils/ast.js';
import { traverse } from '../utils/traverse.js';
import { Suppressions } from '../utils/suppress.js';
import { emptyResult } from '../types.js';
import type { Finding, ProjectContext, ScanResult, Scanner } from '../types.js';

/**
 * Calls that prove the caller's identity was checked server-side.
 * Matched on the dotted callee name (suffix match) so `supabase.auth.getUser`,
 * `client.auth.getUser` and a bare `getUser` all hit.
 */
const AUTH_CALLS = [
  'auth.getUser', 'auth.getClaims', 'getUser', 'getSession',
  'getServerSession', 'getServerAuthSession', 'currentUser', 'auth', 'clerkClient',
  'getAuth', 'validateRequest', 'verifySession', 'requireUser', 'requireAuth',
  'requireSession', 'assertAuthenticated', 'getCurrentUser', 'getLoggedInUser',
  'getToken', 'verifyToken', 'verifyIdToken', 'protect', 'ensureUser',
];

/** Higher-order wrappers that apply auth (and often validation) for the action. */
const AUTH_WRAPPERS = [
  'withAuth', 'withUser', 'withSession', 'authedProcedure', 'protectedProcedure',
  'authActionClient', 'authenticatedAction', 'actionClient', 'createSafeActionClient',
  'createServerAction', 'safeAction', 'guarded', 'requireAuth', 'withGuard',
];

/** Data-writing calls across Supabase, Prisma, Drizzle, Mongoose and raw SQL. */
const MUTATION_CALLS = new Set([
  'insert', 'update', 'upsert', 'delete', 'create', 'createMany', 'updateMany',
  'deleteMany', 'upsertMany', 'destroy', 'save', 'remove', 'findOneAndUpdate',
  'findOneAndDelete', 'updateOne', 'updateMany', 'deleteOne', 'insertOne',
  'insertMany', 'replaceOne', 'bulkWrite', 'increment', 'decrement',
]);

/** Runtime schema validation. Absence of all of these on a parameterised action is a finding. */
const VALIDATION_CALLS = new Set([
  'parse', 'safeParse', 'parseAsync', 'safeParseAsync', 'validate', 'validateSync',
  'assert', 'check', 'decode', 'is', 'coerce', 'cast', 'schema', 'input', 'with',
]);

/**
 * Verification calls that make an inbound webhook trustworthy.
 */
const SIGNATURE_CHECKS = [
  'webhooks.constructEvent', 'constructEvent', 'constructEventAsync', 'verifyHeader',
  'verify', 'verifySignature', 'createHmac', 'timingSafeEqual', 'Webhook', 'validateRequest',
  'verifyWebhook', 'verifyWebhookSignature',
];

/** Schema escape hatches that make validation decorative. */
const LOOSE_SCHEMA = /\.passthrough\s*\(|z\s*\.\s*(any|unknown)\s*\(|\.catchall\s*\(/g;

const SERVICE_ROLE_HINTS = [
  'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SERVICE_KEY', 'SERVICE_ROLE_KEY',
  'SUPABASE_SECRET_KEY',
];

/** Identifiers that plausibly carry the authenticated principal's id. */
const OWNER_HINTS = [
  'user.id', 'user?.id', 'session.user.id', 'userId', 'user_id', 'auth.uid',
  'currentUser.id', 'ctx.user', 'claims.sub', 'uid',
];

function matchesAny(name: string, list: string[]): boolean {
  for (const candidate of list) {
    if (name === candidate || name.endsWith('.' + candidate)) return true;
  }
  return false;
}

interface ActionInfo {
  name: string;
  line: number;
  params: number;
  hasAuth: boolean;
  hasMutation: boolean;
  hasRead: boolean;
  hasValidation: boolean;
  serviceRoleLine: number | null;
  ownerScoped: boolean;
  mutationLine: number | null;
  /** Line of a Supabase `auth.getSession()` used where getUser() is required. */
  getSessionLine: number | null;
  hasSignatureCheck: boolean;
  /** Line where a whole request body is spread into a write. */
  spreadLine: number | null;
  looseSchemaLine: number | null;
  readsAuthHeader: boolean;
}

function analyseFunction(path: any, name: string): ActionInfo {
  const node = path.node;
  const info: ActionInfo = {
    name,
    line: node.loc?.start.line ?? 0,
    params: (node.params ?? []).length,
    hasAuth: false,
    hasMutation: false,
    hasRead: false,
    hasValidation: false,
    serviceRoleLine: null,
    ownerScoped: false,
    mutationLine: null,
    getSessionLine: null,
    hasSignatureCheck: false,
    spreadLine: null,
    looseSchemaLine: null,
    readsAuthHeader: false,
  };

  const inspect = (inner: any) => {
    const full = calleeName(inner.node.callee);
    const tail = calleeTail(inner.node.callee);

    // `supabase.auth.getSession()` reads the cookie without asking the auth
    // server whether the token is still valid, so it proves nothing on the
    // server. It must not satisfy the auth check via the generic `getSession`
    // entry, which exists for hand-rolled helpers.
    const isSupabaseGetSession = /(^|\.)auth\.getSession$/.test(full);
    if (isSupabaseGetSession) {
      info.getSessionLine ??= inner.node.loc?.start.line ?? info.line;
    } else if (matchesAny(full, AUTH_CALLS)) {
      info.hasAuth = true;
    }
    if (matchesAny(full, AUTH_WRAPPERS)) info.hasAuth = true;
    if (matchesAny(full, SIGNATURE_CHECKS)) info.hasSignatureCheck = true;
    if (VALIDATION_CALLS.has(tail)) info.hasValidation = true;
    if (MUTATION_CALLS.has(tail)) {
      info.hasMutation = true;
      if (info.mutationLine === null) {
        info.mutationLine = inner.node.loc?.start.line ?? info.line;
      }
      // `.update({ ...body })` writes whatever keys the caller chose to send.
      for (const arg of inner.node.arguments ?? []) {
        const props = arg?.type === 'ObjectExpression' ? arg.properties : null;
        if (!props) continue;
        for (const prop of props) {
          if (prop?.type !== 'SpreadElement') continue;
          const spreadOf = calleeName(prop.argument);
          if (/^(this|process|env)\b/.test(spreadOf)) continue;
          info.spreadLine ??= prop.loc?.start.line ?? info.line;
        }
      }
    }
    if (tail === 'from' || tail === 'select' || tail === 'findMany' || tail === 'findUnique' || tail === 'findFirst') {
      info.hasRead = true;
    }
    // Raw SQL: db.query(`DELETE FROM ...`) / sql`UPDATE ...`
    if (tail === 'query' || tail === 'execute' || tail === 'unsafe' || tail === 'raw') {
      for (const arg of inner.node.arguments ?? []) {
        const text =
          arg?.type === 'StringLiteral'
            ? arg.value
            : arg?.type === 'TemplateLiteral'
              ? arg.quasis.map((q: any) => q.value.raw).join(' ')
              : '';
        if (/\b(insert\s+into|update\s+|delete\s+from|drop\s+|alter\s+)/i.test(text)) {
          info.hasMutation = true;
          if (info.mutationLine === null) {
            info.mutationLine = inner.node.loc?.start.line ?? info.line;
          }
        }
      }
    }
  };

  path.traverse({
    CallExpression: inspect,
    OptionalCallExpression: inspect,
    TaggedTemplateExpression(inner: any) {
      const tag = calleeName(inner.node.tag);
      if (!/(^|\.)sql$/.test(tag)) return;
      const text = inner.node.quasi.quasis.map((q: any) => q.value.raw).join(' ');
      if (/\b(insert\s+into|update\s+|delete\s+from)/i.test(text)) {
        info.hasMutation = true;
        if (info.mutationLine === null) {
          info.mutationLine = inner.node.loc?.start.line ?? info.line;
        }
      }
    },
    MemberExpression(inner: any) {
      const full = calleeName(inner.node);
      if (/headers\.get$/.test(full) || full.endsWith('CRON_SECRET')) info.readsAuthHeader = true;
      for (const hint of SERVICE_ROLE_HINTS) {
        if (full.endsWith(hint)) {
          info.serviceRoleLine ??= inner.node.loc?.start.line ?? info.line;
        }
      }
      for (const hint of OWNER_HINTS) {
        if (full === hint || full.endsWith('.' + hint)) info.ownerScoped = true;
      }
    },
    Identifier(inner: any) {
      if (SERVICE_ROLE_HINTS.includes(inner.node.name)) {
        info.serviceRoleLine ??= inner.node.loc?.start.line ?? info.line;
      }
      if (inner.node.name === 'userId' || inner.node.name === 'user_id') {
        info.ownerScoped = true;
      }
    },
  });

  // An action wrapped by an auth HOC inherits the check from its wrapper.
  let parent = path.parentPath;
  let hops = 0;
  while (parent && hops++ < 4) {
    if (parent.node?.type === 'CallExpression') {
      if (matchesAny(calleeName(parent.node.callee), AUTH_WRAPPERS)) info.hasAuth = true;
      if (VALIDATION_CALLS.has(calleeTail(parent.node.callee))) info.hasValidation = true;
    }
    parent = parent.parentPath;
  }

  return info;
}

const HTTP_MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function isRouteHandlerFile(relPath: string): boolean {
  return /(^|\/)(app|src\/app)\/.*\/route\.(t|j)sx?$/.test(relPath);
}

export const serverActionsScanner: Scanner = {
  name: 'Next.js Server Actions & Route Handlers',

  applies(ctx) {
    return ctx.framework.nextjs !== null || ctx.files.some(isScript);
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let actionCount = 0;
    let routeCount = 0;

    for (const file of ctx.files) {
      if (!isScript(file)) continue;
      const source = read(file);
      if (source === null) continue;

      const relPath = rel(ctx.root, file);
      const routeFile = isRouteHandlerFile(relPath);
      const moduleUseServer = /^\s*(['"])use server\1/m.test(source.slice(0, 400));
      if (!moduleUseServer && !routeFile && !source.includes('use server')) continue;

      const ast = parseSource(source, file);
      if (!ast) {
        result.warnings.push(`could not parse ${relPath}`);
        continue;
      }
      const suppress = new Suppressions(source);
      const programUseServer = moduleUseServer || hasDirective(ast.program, 'use server');

      const push = (f: Omit<Finding, 'file'> & { line: number }) => {
        if (suppress.suppressed(f.line, f.id)) return;
        result.findings.push({
          ...f,
          file: relPath,
          snippet: snippetAt(source, f.line),
        });
      };

      const handle = (path: any, name: string, exported: boolean, httpMethod?: string) => {
        const node = path.node;
        const inlineUseServer = hasDirective(node, 'use server');
        const isAction = exported && (programUseServer || inlineUseServer);
        const isRoute = Boolean(httpMethod);
        if (!isAction && !isRoute) return;

        const info = analyseFunction(path, name);
        if (isAction) actionCount++;
        if (isRoute) routeCount++;

        const kind = isRoute ? 'Route Handler' : 'Server Action';
        const exposure = isRoute
          ? `\`${httpMethod} ${relPath.replace(/^(src\/)?app/, '').replace(/\/route\.[tj]sx?$/, '') || '/'}\` is a public HTTP endpoint.`
          : 'Server Actions compile to public HTTP POST endpoints — anyone can invoke this by ID, the UI is not a gate.';

        const writes = info.hasMutation || (isRoute && HTTP_MUTATION_METHODS.has(httpMethod!));
        const isWebhook =
          isRoute && httpMethod === 'POST' && /webhook|\bhooks?\b|stripe|clerk|svix/i.test(relPath);
        const isCron = isRoute && /(^|\/)(cron|scheduled|jobs?)(\/|$)/i.test(relPath);

        if (writes && !info.hasAuth && info.getSessionLine === null) {
          push({
            id: 'CTS001',
            severity: 'critical',
            title: `Missing ${kind} authorization`,
            detail:
              `${kind} \`${name}\` performs a database mutation without verifying the caller. ` +
              exposure,
            fix:
              'Resolve and check the session before touching the database, e.g.\n' +
              '  const { data: { user } } = await supabase.auth.getUser()\n' +
              "  if (!user) throw new Error('Unauthorized')\n" +
              'then scope the write to that user. A wrapper such as next-safe-action’s ' +
              '`authActionClient` also satisfies this check.',
            line: info.mutationLine ?? info.line,
            cwe: 'CWE-306: Missing Authentication for Critical Function',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }

        if (info.params > 0 && writes && !info.hasValidation) {
          push({
            id: 'CTS002',
            severity: 'high',
            title: `${kind} input is never validated at runtime`,
            detail:
              `\`${name}\` accepts caller-supplied arguments and writes them to the database ` +
              'without runtime schema validation. TypeScript types are erased at runtime, so a ' +
              'crafted payload can carry extra fields straight into the write (mass assignment).',
            fix:
              'Parse the input before use:\n' +
              "  const parsed = MySchema.safeParse(raw)\n" +
              "  if (!parsed.success) throw new Error('Invalid input')\n" +
              'and pass `parsed.data` — never the raw argument — to the query.',
            line: info.line,
            cwe: 'CWE-20: Improper Input Validation',
            owasp: 'A05:2025 - Injection',
            meta: { action: name, kind },
          });
        }

        if (info.serviceRoleLine !== null) {
          push({
            id: 'CTS003',
            severity: 'critical',
            title: `Service-role key used inside a ${kind}`,
            detail:
              `\`${name}\` builds a Supabase client with the service-role key. That key bypasses ` +
              'every Row Level Security policy, so any authorization bug in this function exposes ' +
              'the whole table rather than one row.',
            fix:
              'Use the request-scoped anon client (`createClient()` from your server helper) so RLS ' +
              'still applies. Reserve the service-role key for trusted background jobs that no user ' +
              'request can reach.',
            line: info.serviceRoleLine,
            cwe: 'CWE-250: Execution with Unnecessary Privileges',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }

        if (info.getSessionLine !== null && !info.hasAuth) {
          push({
            id: 'CTS041',
            severity: 'high',
            title: `${kind} authenticates with getSession() instead of getUser()`,
            detail:
              `\`${name}\` calls \`supabase.auth.getSession()\` to decide who the caller is. On the ` +
              'server that only decodes the session cookie — it never asks the auth server whether the ' +
              'token is still valid, so a forged or revoked cookie passes. Supabase documents ' +
              '`getSession()` as safe on the client only.',
            fix:
              'Use `const { data: { user } } = await supabase.auth.getUser()` instead, which revalidates ' +
              'the JWT against the auth server, and branch on `user`.',
            line: info.getSessionLine,
            cwe: 'CWE-287: Improper Authentication',
            owasp: 'A07:2025 - Authentication Failures',
            meta: { action: name, kind },
          });
        }

        if (info.spreadLine !== null) {
          push({
            id: 'CTS043',
            severity: 'high',
            title: `${kind} spreads caller-supplied data into a write`,
            detail:
              `\`${name}\` spreads an object it received into a database write, so every key the ` +
              'caller chose to send is written. Adding `"is_admin": true` or `"credits": 999999` to the ' +
              'request body is enough to set those columns — the classic mass-assignment escalation.',
            fix:
              'Write an explicit column list built from validated fields — ' +
              '`{ name: parsed.data.name }` — rather than spreading the request body.',
            line: info.spreadLine,
            cwe: 'CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }

        if (isWebhook && !info.hasSignatureCheck) {
          push({
            id: 'CTS042',
            severity: 'critical',
            title: 'Webhook endpoint does not verify its signature',
            detail:
              `\`${relPath}\` looks like a webhook receiver but nothing in \`${name}\` verifies the ` +
              'provider signature. Webhook URLs are not secret and the payload is entirely ' +
              'attacker-controlled, so anyone who learns the URL can post a forged event — a fake ' +
              '`checkout.session.completed` grants themselves a paid plan.',
            fix:
              'Verify before trusting anything in the body, e.g. ' +
              '`stripe.webhooks.constructEvent(rawBody, sig, process.env.STRIPE_WEBHOOK_SECRET)` ' +
              'for Stripe or `new Webhook(secret).verify(payload, headers)` for Clerk/svix. Read the ' +
              'raw body, not the parsed JSON.',
            line: info.line,
            cwe: 'CWE-345: Insufficient Verification of Data Authenticity',
            owasp: 'A08:2025 - Software & Data Integrity Failures',
            meta: { kind, route: relPath },
          });
        }

        if (isCron && !info.readsAuthHeader && !info.hasAuth) {
          push({
            id: 'CTS046',
            severity: 'high',
            title: 'Cron endpoint is callable by anyone',
            detail:
              `\`${relPath}\` is a scheduled job route, but \`${name}\` checks neither a shared ` +
              'secret nor a session. The path is public HTTP like any other, so anyone can trigger the ' +
              'job — repeatedly, and at a time of their choosing.',
            fix:
              'Compare an `Authorization` header against `process.env.CRON_SECRET` and return 401 on ' +
              'mismatch. Vercel Cron sends that header automatically when the variable is set.',
            line: info.line,
            cwe: 'CWE-306: Missing Authentication for Critical Function',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { kind, route: relPath },
          });
        }

        if (writes && info.hasAuth && !info.ownerScoped && info.params > 0) {
          push({
            id: 'CTS004',
            severity: 'medium',
            title: `${kind} mutation is authenticated but not owner-scoped`,
            detail:
              `\`${name}\` checks that *someone* is logged in, then mutates a row identified only by ` +
              'a caller-supplied argument. Any logged-in user can pass another tenant’s id (IDOR).',
            fix:
              'Constrain the write to the authenticated principal, e.g. ' +
              "`.eq('id', id).eq('user_id', user.id)`, or rely on an RLS policy that compares " +
              '`auth.uid()` against the owning column.',
            line: info.mutationLine ?? info.line,
            cwe: 'CWE-639: Authorization Bypass Through User-Controlled Key',
            owasp: 'A01:2025 - Broken Access Control',
            meta: { action: name, kind },
          });
        }
      };

      // Validation that opts out of validating. Reported per file, since the
      // schema is usually declared at module scope, away from the action.
      if (programUseServer || routeFile) {
        LOOSE_SCHEMA.lastIndex = 0;
        const loose = LOOSE_SCHEMA.exec(source);
        if (loose) {
          const line = source.slice(0, loose.index).split('\n').length;
          push({
            id: 'CTS044',
            severity: 'medium',
            title: 'Schema opts out of validating',
            detail:
              `\`${loose[0]}\` in a server-side module means the schema accepts keys it does not ` +
              'declare. Input then passes validation while still carrying whatever extra fields the ' +
              'caller attached, which is the situation the schema was added to prevent.',
            fix:
              'Drop `.passthrough()` / `.catchall()` and replace `z.any()` or `z.unknown()` with the ' +
              'shape you actually expect. Zod strips unknown keys by default — that default is the point.',
            line,
            cwe: 'CWE-20: Improper Input Validation',
            owasp: 'A05:2025 - Injection',
          });
        }
      }

      traverse(ast, {
        ExportNamedDeclaration(path: any) {
          const decl = path.node.declaration;
          if (!decl) return;
          if (decl.type === 'FunctionDeclaration' && decl.id) {
            const name = decl.id.name;
            const method = routeFile && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(name) ? name : undefined;
            handle(path.get('declaration'), name, true, method);
          } else if (decl.type === 'VariableDeclaration') {
            decl.declarations.forEach((d: any, i: number) => {
              if (d.id?.type !== 'Identifier') return;
              if (d.init?.type !== 'ArrowFunctionExpression' && d.init?.type !== 'FunctionExpression') return;
              const name = d.id.name;
              const method = routeFile && /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$/.test(name) ? name : undefined;
              // cleartoship-ignore VG010 — Babel's AST accessor, not a SQL call;
              // the rule's verb list includes the generic `get`.
              const initPath = path.get(`declaration.declarations.${i}.init`);
              handle(initPath, name, true, method);
            });
          }
        },
        ExportDefaultDeclaration(path: any) {
          const decl = path.node.declaration;
          if (decl?.type === 'FunctionDeclaration' || decl?.type === 'ArrowFunctionExpression') {
            handle(path.get('declaration'), decl.id?.name ?? 'default', true);
          }
        },
      });
    }

    if (actionCount > 0) {
      result.checks.push({
        label: `Server Action authorization (${actionCount} action${actionCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' || f.id === 'CTS003'),
      });
    }
    if (routeCount > 0) {
      result.checks.push({
        label: `Route Handler authorization (${routeCount} handler${routeCount === 1 ? '' : 's'} analysed)`,
        passed: !result.findings.some((f) => f.id === 'CTS001' && f.meta?.kind === 'Route Handler'),
      });
    }
    if (actionCount === 0 && routeCount === 0) {
      result.checks.push({
        label: 'Server Action authorization',
        passed: true,
        note: 'no Server Actions or Route Handlers found',
      });
    }
    return result;
  },
};

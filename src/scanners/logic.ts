import { read, rel, isScript, snippetAt } from '../utils/files.js';
import { adjustForPath } from '../utils/paths.js';
import { parseSource, calleeName, calleeTail } from '../utils/ast.js';
import { traverse } from '../utils/traverse.js';
import { Suppressions } from '../utils/suppress.js';
import { emptyResult } from '../types.js';
import type { Finding, ScanResult, Scanner } from '../types.js';

/**
 * Cross-cutting logic checks for OWASP categories a pattern scanner can only
 * touch in specific, high-signal slices:
 *   A09 (Logging Failures)      — secrets/PII written to logs
 *   A10 (Exceptional Conditions)— fail-open / swallowed errors on a security path
 *   A08 (Integrity Failures)    — insecure deserialization of untrusted data
 *
 * Each rule is deliberately narrow: the goal is a true positive a developer will
 * act on, not coverage for its own sake.
 *
 * The LLM/agent-specific checks (CTS080-085) live in `agent-logic.ts` — see that
 * file for the OWASP LLM Top 10 categories it covers.
 */

const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'fatal', 'verbose']);
const LOG_OBJECTS = /^(console|logger|log|pino|winston|fastify\.log|req\.log|ctx\.log|this\.logger)$/i;

/** A property/identifier name that names a real secret or piece of PII. */
const SENSITIVE_NAME =
  /(?:^|[._])(password|passwd|pwd|secret|secrets|token|tokens|apikey|api_key|authorization|auth_?token|accesstoken|access_token|refreshtoken|refresh_token|sessiontoken|session_token|privatekey|private_key|clientsecret|client_secret|creditcard|card_?number|cardnumber|cvv|cvc|ssn|social_?security|passport|jwt)(?:$|[._])/i;

/** Reading a whole request/response body into a log dumps everything in it. */
const BODY_EXPR = /(?:^|\.)(body|rawBody|payload)$/;

/**
 * Methods that read a body off a `Response`. `await res.json()` and
 * `await request.json()` are the same call shape, so the method name alone
 * cannot say which side of the wire a body came from -- the receiver can.
 */
const BODY_READERS = new Set(['json', 'text', 'arrayBuffer', 'formData', 'blob', 'bytes']);

/** Receivers that name an inbound request in Express, Hono, Workers and Next. */
const REQUEST_RECEIVER = /^(?:req|request|event|ctx|c)$/i;

/** Promise combinators that wrap the call that actually read the body. */
const PROMISE_CHAIN = new Set(['catch', 'then', 'finally']);

/** Strip the wrappers that sit between a declarator and the call underneath. */
function unwrapExpr(node: any): any {
  let n = node;
  while (
    n &&
    (n.type === 'TSAsExpression' ||
      n.type === 'TSSatisfiesExpression' ||
      n.type === 'TSNonNullExpression' ||
      n.type === 'TSTypeAssertion' ||
      n.type === 'ParenthesizedExpression' ||
      n.type === 'AwaitExpression')
  ) {
    n = n.expression ?? n.argument;
  }
  return n;
}

/** `res.json().catch(() => ({}))` -> `res.json()`. */
function stripPromiseChain(node: any): any {
  let n = node;
  while (
    n?.type === 'CallExpression' &&
    n.callee?.type === 'MemberExpression' &&
    PROMISE_CHAIN.has(n.callee.property?.name)
  ) {
    n = unwrapExpr(n.callee.object);
  }
  return n;
}

/** The initializer of `name`'s binding in this scope, or null. */
function initializerOf(scope: any, name: string): any {
  try {
    return scope?.getBinding?.(name)?.path?.node?.init ?? null;
  } catch {
    return null;
  }
}

/**
 * Which side of the wire a logged `body`/`payload` came from.
 *
 * This resolves the binding chain rather than guessing from the name, because
 * the name is exactly what is ambiguous: a local `const body = await
 * res.json()` holding an upstream error payload and a destructured request
 * body are both called `body`. Reported by the session that owns app B, on a
 * `selectRows` helper that logs a failed PostgREST read's error object -- for
 * which "whatever a caller put in the request body" was simply untrue.
 *
 * `'unknown'` keeps the original request-body wording, so an unresolvable
 * chain loses no detection.
 */
function bodySide(scope: any, arg: any, depth = 0): 'request' | 'upstream' | 'unknown' {
  let receiver: any = null;
  if (depth > 3) return 'unknown';

  if (arg.type === 'MemberExpression') {
    receiver = arg.object;
  } else if (arg.type === 'Identifier') {
    const init = stripPromiseChain(unwrapExpr(initializerOf(scope, arg.name)));
    // `const payload = req.body` -- one more hop, same question.
    if (init?.type === 'MemberExpression') return bodySide(scope, init, depth + 1);
    if (init?.type !== 'CallExpression') return 'unknown';
    const callee = init.callee;
    if (callee?.type !== 'MemberExpression') return 'unknown';
    if (!BODY_READERS.has(callee.property?.name)) return 'unknown';
    receiver = callee.object;
  }

  if (receiver?.type !== 'Identifier') return 'unknown';
  if (REQUEST_RECEIVER.test(receiver.name)) return 'request';

  // The decisive signal: the receiver itself came from `fetch(...)`.
  const src = unwrapExpr(initializerOf(scope, receiver.name));
  if (src?.type === 'CallExpression' && calleeTail(src.callee) === 'fetch') return 'upstream';
  return 'unknown';
}

/** Deserializers that can instantiate objects or run code from their input. */
const UNSAFE_DESERIALIZE = [
  'unserialize', // node-serialize / serialize-to-js — RCE on crafted input
  'deserialize',
  'funcster.deepDeserialize', // cleartoship-ignore VG070 — rule-name data, not a call
  'pickle.loads', // python
  'pickle.load',
  'cPickle.loads',
  'yaml.unsafe_load', // python
];

/**
 * Function names that signal the body is making a security decision.
 *
 * `ensure` used to count on its own, so `ensureDir() { try { mkdirSync … }
 * catch {} }` — the idiomatic "create it unless it exists" — was reported as a
 * security check swallowing its error. `ensure` is a security word only when
 * what it ensures is one.
 */
const SECURITY_FN =
  /(verify|validate|authenticate|authorize|auth|check(?:auth|access|permission)?|hasaccess|haspermission|isallowed|isauthorized|canaccess|ensure(?:admin|user|owner|member|role|permission|access|session|loggedin|signedin|login|allowed|authorized|authenticated)|guard|require(?:auth|user|admin)?)/i;

/** The name a property key spells, when it spells one. */
function keyName(key: any): string {
  if (!key) return '';
  if (key.type === 'Identifier') return key.name;
  if (key.type === 'StringLiteral') return key.value;
  if (key.type === 'PrivateName') return key.id?.name ?? '';
  return '';
}

/**
 * Name of the nearest enclosing named function, for judging whether a block
 * guards a security decision.
 *
 * Only declarations, function expressions and variables were read, so the two
 * places auth code most often lives were invisible: an object method (NextAuth's
 * `authorize(credentials) { … catch { return user } }`) and a class method
 * (`class Guard { verify(token) { … catch { return true } } }`). Both are named
 * by their key.
 */
function enclosingFunctionName(path: any): string {
  let p = path.parentPath;
  let hops = 0;
  while (p && hops++ < 12) {
    const n = p.node;
    switch (n?.type) {
      case 'FunctionDeclaration':
        return n.id?.name ?? '';
      case 'ObjectMethod':
      case 'ClassMethod':
      case 'ClassPrivateMethod':
        return keyName(n.key);
      case 'FunctionExpression':
      case 'ArrowFunctionExpression': {
        if (n.id?.name) return n.id.name;
        // Named by where it is put: `const verify = () => …`, `{ verify: () => … }`,
        // `class { verify = () => … }`.
        const parent = p.parentPath?.node;
        if (parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier') return parent.id.name;
        if (
          (parent?.type === 'ObjectProperty' ||
            parent?.type === 'ClassProperty' ||
            parent?.type === 'ClassPrivateProperty') &&
          parent.value === n
        ) {
          return keyName(parent.key);
        }
        // An anonymous callback (`items.forEach(() => …)`): keep looking outward
        // for the function it sits in.
        break;
      }
    }
    p = p.parentPath;
  }
  return '';
}

/** Values a security check must never return from a swallowed error (fail-open). */
function isPermissiveReturn(node: any): boolean {
  if (!node) return false;
  if (node.type === 'BooleanLiteral' && node.value === true) return true;
  if (node.type === 'Identifier' && /^(user|session|account|token|claims)$/i.test(node.name)) return true;
  if (node.type === 'ObjectExpression') {
    return node.properties.some(
      (p: any) =>
        p?.key &&
        /^(authorized|authenticated|valid|allowed|ok|success)$/i.test(p.key.name ?? p.key.value) &&
        p.value?.value === true,
    );
  }
  if (node.type === 'CallExpression') {
    // next() with no error argument lets the request continue.
    return calleeTail(node.callee) === 'next' && (node.arguments ?? []).length === 0;
  }
  return false;
}

export const logicScanner: Scanner = {
  name: 'Logging, exception-handling & deserialization',

  applies(ctx) {
    return ctx.files.some((f) => isScript(f) || f.endsWith('.py'));
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let analysed = 0;
    const unanalysed: string[] = [];
    const failed: string[] = [];

    for (const file of ctx.files) {
      const script = isScript(file);
      const python = file.endsWith('.py');
      if (!script && !python) continue;
      const relPath = rel(ctx.root, file);
      try {
      const source = read(file);
      if (source === null) continue;
      // A swallowed error or a logged token in a maintenance script is a
      // smaller problem than the same line inside a request handler.
      const place = (f: any) => {
        const placed = adjustForPath(f.severity, relPath);
        return { ...f, severity: placed.severity, detail: f.detail + placed.note };
      };
      const suppress = new Suppressions(source, relPath);

      const push = (f: Omit<Finding, 'file'> & { line: number }) => {
        if (suppress.suppressed(f.line, f.id)) return;
        result.findings.push({ ...place(f), file: relPath, snippet: snippetAt(source, f.line) });
      };

      // Python is regex-only (no JS AST). Cover its highest-signal cases.
      if (python) {
        analysed++;
        source.split('\n').forEach((lineText, i) => {
          const line = i + 1;
          if (/\b(pickle|cPickle)\.loads?\s*\(/.test(lineText) || /\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)/.test(lineText)) {
            push({
              id: 'CTS072',
              severity: 'high',
              title: 'Insecure deserialization of untrusted data',
              detail:
                'This call deserializes input with a loader that can construct arbitrary objects — ' +
                '`pickle` and unqualified `yaml.load` both execute code embedded in a crafted payload.',
              fix: 'Use `yaml.safe_load` (or `Loader=yaml.SafeLoader`); never `pickle.loads` on data that crossed a trust boundary. Prefer JSON for untrusted input.',
              line,
              cwe: 'CWE-502: Deserialization of Untrusted Data',
              owasp: 'A08:2025 - Software & Data Integrity Failures',
            });
          }
        });
        continue;
      }

      const ast = parseSource(source, file);
      if (!ast) {
        // Skipping it silently read as "nothing wrong here" — the worst
        // answer a scanner can give about a file it never analysed.
        unanalysed.push(relPath);
        continue;
      }
      analysed++;

      traverse(ast, {
        CallExpression(path: any) {
          const node = path.node;
          const tail = calleeTail(node.callee);
          const full = calleeName(node.callee);

          // --- A09: secrets / PII written to a log ---
          const base = full.slice(0, full.lastIndexOf('.'));
          const isLog =
            LOG_METHODS.has(tail) && (LOG_OBJECTS.test(base) || base === '' || /log$/i.test(base));
          if (isLog) {
            for (const arg of node.arguments ?? []) {
              // Only value expressions count — a string message that merely
              // contains the word "password" is not logging a password.
              if (arg.type === 'StringLiteral' || arg.type === 'TemplateLiteral') continue;
              const name = arg.type === 'MemberExpression' || arg.type === 'Identifier' ? calleeName(arg) : '';
              const sensitive = name && SENSITIVE_NAME.test(name);
              const wholeBody = name && BODY_EXPR.test(name);
              if (sensitive || wholeBody) {
                // A whole-body log is only a *request* body when the body came
                // from the request. An upstream response body read off a
                // `fetch` is a different finding with a different remedy, so
                // it is re-worded rather than dropped: a database layer's
                // error payload carries diagnostic fields that can echo row
                // values, which is worth saying, but no caller put them there.
                const side = wholeBody && !sensitive ? bodySide(path.scope, arg) : 'request';
                const upstream = side === 'upstream';
                push({
                  id: 'CTS070',
                  severity: !wholeBody || sensitive ? 'high' : upstream ? 'low' : 'medium',
                  title: sensitive
                    ? 'Secret or PII written to logs'
                    : upstream
                      ? 'Upstream response body written to logs'
                      : 'Request body written to logs',
                  detail:
                    (wholeBody && !sensitive
                      ? upstream
                        ? `\`${name}\` holds a body read from an upstream \`fetch\` response, and is logged ` +
                          'in full. Nothing a caller sent is in it, so this is not a request-body leak — but ' +
                          'an error payload is not only the fields you typed into its cast: PostgREST returns ' +
                          '`details` and `hint`, which can quote the offending row, and a `as {code, message}` ' +
                          'annotation narrows the type without narrowing what arrives.'
                        : `\`${name}\` is logged in full, so whatever a caller put in the request body — ` +
                          'passwords, tokens, personal data — lands in your log store and anywhere it is shipped.'
                      : `\`${name}\` is written to a log. Logs are retained, replicated to aggregators and ` +
                        'often world-readable to a whole team; a credential or piece of PII there is a ' +
                        'leak that outlives the request.'),
                  fix: upstream
                    ? 'Log the fields you actually need — a status and an error code — rather than the whole ' +
                      'object: `console.error(table, res.status, body.code)`. If the full payload is wanted ' +
                      'for debugging, pick the keys explicitly so a new upstream field cannot start arriving ' +
                      'in your logs unreviewed.'
                    : 'Do not log the raw value. Log a non-reversible reference (a user id, a hash prefix) ' +
                      'or redact the field before logging.',
                  line: node.loc?.start.line ?? 0,
                  cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
                  owasp: 'A09:2025 - Security Logging & Alerting Failures',
                  meta: { logged: name, side },
                });
                break;
              }
            }
          }

          // --- A08: insecure deserialization ---
          if (UNSAFE_DESERIALIZE.some((d) => full === d || full.endsWith('.' + d) || tail === d)) {
            const arg = (node.arguments ?? [])[0];
            // A string literal is a fixed, trusted payload; only flag dynamic input.
            if (arg && arg.type !== 'StringLiteral') {
              push({
                id: 'CTS072',
                severity: 'high',
                title: 'Insecure deserialization of untrusted data',
                detail:
                  `\`${full}(...)\` reconstructs objects from its input. Deserializers of this kind can ` +
                  'instantiate arbitrary types and invoke their side effects, so a crafted payload is ' +
                  'remote code execution — this is why `JSON.parse` is safe and these are not.',
                fix:
                  'Deserialize untrusted data with `JSON.parse` only. If you need richer types, validate ' +
                  'the parsed shape with a schema; never hand attacker-controlled bytes to an object ' +
                  'deserializer.',
                line: node.loc?.start.line ?? 0,
                cwe: 'CWE-502: Deserialization of Untrusted Data',
                owasp: 'A08:2025 - Software & Data Integrity Failures',
              });
            }
          }
        },

        // --- A10: fail-open / swallowed error on a security path ---
        CatchClause(path: any) {
          const node = path.node;
          const body = node.body?.body ?? [];

          // Name of the nearest enclosing function, to tell whether this catch
          // guards a security decision.
          const fnName = enclosingFunctionName(path);
          const securityContext = SENSITIVE_NAME.test(fnName) || SECURITY_FN.test(fnName);
          if (!securityContext) return;

          const returns = body.filter((s: any) => s.type === 'ReturnStatement');
          const permissive = returns.some((r: any) => isPermissiveReturn(r.argument));
          const empty = body.length === 0;
          const swallows =
            empty ||
            body.every(
              (s: any) =>
                s.type === 'ReturnStatement' ||
                (s.type === 'ExpressionStatement' &&
                  /console|log/i.test(calleeName(s.expression?.callee ?? {}))),
            );

          if (permissive || (empty && securityContext) || (swallows && permissive)) {
            push({
              id: 'CTS071',
              severity: permissive ? 'high' : 'medium',
              title: permissive
                ? 'Security check fails open on error'
                : 'Security check swallows its error',
              detail:
                `The catch block in \`${fnName || 'this function'}\` ` +
                (permissive
                  ? 'returns a permissive value (authorized / a user / next()) when the guarded ' +
                    'operation throws. An attacker who can make the check error — a malformed token, a ' +
                    'timeout — is then let straight through.'
                  : 'discards the error from a security-relevant operation. A verification that throws ' +
                    'is a failure, not a pass; swallowing it hides the failure and risks failing open.'),
              fix:
                'Fail closed: on error, deny — `return false` / throw / respond 401 — and log the error. ' +
                'Never return a success value from the catch of a security check.',
              line: node.loc?.start.line ?? 0,
              cwe: 'CWE-703: Improper Check or Handling of Exceptional Conditions',
              owasp: 'A10:2025 - Mishandling of Exceptional Conditions',
              meta: { function: fnName },
            });
          }
        },
      });
      } catch (err) {
        // One file the analysis cannot finish — a 20,000-deep member chain
        // overflows the stack in traversal — costs that file, not the run.
        failed.push(`${relPath} (${err instanceof Error ? err.message : String(err)})`);
      }
    }

    for (const f of unanalysed) {
      result.incomplete!.push(`${f} could not be parsed, so the logging, error-handling and deserialization checks did not run on it.`);
    }
    for (const f of failed) {
      result.incomplete!.push(`The logging, error-handling and deserialization checks could not finish ${f}.`);
    }

    result.checks.push({
      label: `Logging, error-handling & deserialization (${analysed} file${analysed === 1 ? '' : 's'})`,
      passed: !result.findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    });
    return result;
  },
};

import { read, rel, isScript, snippetAt } from '../utils/files.js';
import { adjustForPath } from '../utils/paths.js';
import { parseSource, calleeName, calleeTail } from '../utils/ast.js';
import { traverse } from '../utils/traverse.js';
import { Suppressions } from '../utils/suppress.js';
import { emptyResult } from '../types.js';
import { OWASP_LLM } from '../utils/owasp.js';
import type { Finding, ProjectContext, ScanResult, Scanner, Severity } from '../types.js';

/**
 * Cross-cutting logic checks for OWASP categories a pattern scanner can only
 * touch in specific, high-signal slices:
 *   A09 (Logging Failures)      — secrets/PII written to logs
 *   A10 (Exceptional Conditions)— fail-open / swallowed errors on a security path
 *   A08 (Integrity Failures)    — insecure deserialization of untrusted data
 *   LLM01 (Prompt Injection)    — request data concatenated into prompt text
 *   LLM03 (Excessive Agency)    — an agent tool that acts irreversibly, ungated
 *   LLM06 (Unbounded Consumption) — a model call with no ceiling on what it spends
 *   LLM07 (Misinformation)      — a security decision made from the model's answer
 *   LLM08 (Hidden Context)      — a system prompt shipped to the browser
 *   LLM10 (Improper Output Handling) — model output executed or rendered as HTML
 *
 * Each rule is deliberately narrow: the goal is a true positive a developer will
 * act on, not coverage for its own sake.
 */

/** Calls that send a prompt to a model, across the SDKs people actually use. */
const MODEL_CALLS = [
  'chat.completions.create',
  'completions.create',
  'responses.create',
  'messages.create',
  'messages.stream',
  'generateContent',
  'generateText',
  'streamText',
  'generateObject',
  'streamObject',
];

/** Options that put a ceiling on what one call can spend. */
const TOKEN_LIMITS =
  /^(max_tokens|maxTokens|maxOutputTokens|max_output_tokens|max_completion_tokens|maxCompletionTokens|maxSteps|max_steps)$/;

/** Names that hold instructions to the model rather than a user's message. */
const PROMPT_NAME = /^(system|systemPrompt|system_prompt|instructions|prompt|preamble|template)$/i;

/** An interpolation that reads from the request — the untrusted half of a prompt. */
const REQUEST_ROOT =
  /^(req|request|body|params|query|searchParams|formData|payload|input|userInput|message|userMessage|comment|content)$/;

function rootName(node: any): string | null {
  let cur = node;
  let guard = 0;
  while (cur && guard++ < 16) {
    if (cur.type === 'Identifier') return cur.name;
    cur = cur.object ?? cur.expression ?? cur.argument ?? cur.callee;
  }
  return null;
}

function matchesModelCall(name: string): boolean {
  return MODEL_CALLS.some((c) => name === c || name.endsWith('.' + c));
}

const LOG_METHODS = new Set(['log', 'info', 'warn', 'error', 'debug', 'trace', 'fatal', 'verbose']);
const LOG_OBJECTS = /^(console|logger|log|pino|winston|fastify\.log|req\.log|ctx\.log|this\.logger)$/i;

/** A property/identifier name that names a real secret or piece of PII. */
const SENSITIVE_NAME =
  /(?:^|[._])(password|passwd|pwd|secret|secrets|token|tokens|apikey|api_key|authorization|auth_?token|accesstoken|access_token|refreshtoken|refresh_token|sessiontoken|session_token|privatekey|private_key|clientsecret|client_secret|creditcard|card_?number|cardnumber|cvv|cvc|ssn|social_?security|passport|jwt)(?:$|[._])/i;

/** Reading a whole request/response body into a log dumps everything in it. */
const BODY_EXPR = /(?:^|\.)(body|rawBody|payload)$/;

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

/** Function names that signal the body is making a security decision. */
const SECURITY_FN =
  /(verify|validate|authenticate|authorize|auth|check(?:auth|access|permission)?|hasaccess|haspermission|isallowed|isauthorized|canaccess|ensure|guard|require(?:auth|user|admin)?)/i;

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

/**
 * The shape of a tool a model is allowed to invoke on its own: a description, an
 * argument schema, and a body that does the work. Vercel's `tool({...})`, an
 * OpenAI function definition and MCP's `registerTool` all reduce to it.
 */
const TOOL_BODY_KEY = /^(execute|handler|run|fn|func|callback)$/;
const TOOL_SHAPE_KEY = /^(description|parameters|inputSchema|input_schema|schema|args)$/;
const TOOL_REGISTER = /^(registerTool|addTool|setRequestHandler|tool)$/;

/**
 * Actions an agent cannot take back. Ordinary inserts and updates are left out
 * deliberately — an agent that writes a row is the normal case, and reporting
 * every one of those would bury the rule. What is reported is the subset that a
 * wrong answer cannot be undone from: data deleted, money moved, a message sent
 * to somebody, a shell command, a file removed.
 */
const IRREVERSIBLE: [RegExp, string][] = [
  [
    /^(db|prisma|supabase|sql|knex|drizzle|conn|pool|client|collection|table|model|repo|repository)[\w.]*\.(delete|deleteMany|deleteOne|destroy|drop|truncate)$/i,
    'deletes rows',
  ],
  [/(^|\.)\$(execute|query)Raw(Unsafe)?$/, 'executes raw SQL'],
  [/(^|\.)(rmSync|rmdir|rmdirSync|unlink|unlinkSync|rimraf)$|(^|\.)fs\.rm$|^rm$/, 'removes files'],
  // Bare `exec` is the child_process import; `re.exec(s)` is a regex match and
  // must not read as a shell. So a member call has to name the module.
  [
    /^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$|^(child_process|cp|shell)\.(exec|execSync|execFile|spawn|spawnSync)$/,
    'runs a shell command',
  ],
  [/(refunds|charges|paymentIntents|transfers|payouts|invoices|subscriptions)\.(create|cancel|update|del)$/i, 'moves money'],
  [
    /(resend|sendgrid|nodemailer|transporter|mailer|postmark|ses|emails)[\w.]*\.(send|sendMail|sendEmail)$/i,
    'sends email',
  ],
];

/**
 * Anything that puts a person between the model's decision and the effect —
 * a confirmation step, a permission check, a dry run. Its presence is taken as
 * the gate; judging whether the gate is *correct* is not something a static
 * read can do, and claiming otherwise would be the kind of coverage theatre
 * this project avoids.
 *
 * Matched against identifiers and property keys only, never string values. A
 * tool whose `description` says "review this before approving" has written
 * prose, not a gate, and must not be able to talk the rule out of firing.
 */
const APPROVAL_GATE =
  /(confirm|approv|consent|agree|acknowledg|human|operator|reviewer|dry[_-]?run|checkpermission|haspermission|require(admin|user|owner|human)|assertowner|authoriz|authoris|verifyowner|pending)/i;

/** Sinks where a model's answer stops being text and starts being behaviour. */
const OUTPUT_SINKS: [RegExp, string, Severity][] = [
  [/^eval$/, 'evaluated as code', 'critical'],
  [
    /^(exec|execSync|execFile|execFileSync|spawn|spawnSync)$|^(child_process|cp|shell)\.(exec|execSync|execFile|spawn|spawnSync)$/,
    'run as a shell command',
    'critical',
  ],
  [/(^|\.)\$(execute|query)RawUnsafe$/, 'concatenated into raw SQL', 'critical'],
];

/** Answers a model is asked to give when it is being used as a guard. */
const DECISION_WORD =
  /^(yes|no|true|false|allow|allowed|deny|denied|safe|unsafe|approved|rejected|authorized|authorised|admin|ok|okay|pass|fail|valid|invalid|clean|abusive|spam)$/i;

/** Properties that hold the text a model returned, across the SDKs. */
const MODEL_TEXT_PROP = /^(text|content|output_text|outputText|message|choices|candidates|completion)$/;

/**
 * Did this expression come out of a model call — directly, or through a binding
 * that did? Walks the spine of the expression rather than the whole subtree, so
 * `answer.trim()` counts and `{ answer }.other` does not.
 */
function fromModel(node: any, bindings: Set<string>): boolean {
  let cur = node;
  let guard = 0;
  while (cur && guard++ < 24) {
    switch (cur.type) {
      case 'AwaitExpression':
        cur = cur.argument;
        continue;
      case 'TSNonNullExpression':
      case 'TSAsExpression':
      case 'ParenthesizedExpression':
        cur = cur.expression;
        continue;
      case 'MemberExpression':
      case 'OptionalMemberExpression':
        cur = cur.object;
        continue;
      case 'CallExpression':
      case 'OptionalCallExpression':
        if (matchesModelCall(calleeName(cur.callee))) return true;
        cur = cur.callee;
        continue;
      case 'Identifier':
        return bindings.has(cur.name);
      default:
        return false;
    }
  }
  return false;
}

/**
 * Every binding in the file that holds what a model returned. Two passes, so
 * `const res = await generateText(...)` on one line and `const answer = res.text`
 * on the next both count — which is how every one of these SDKs reads in
 * practice.
 */
function collectModelBindings(ast: any): Set<string> {
  const bindings = new Set<string>();
  const record = (id: any) => {
    if (id?.type === 'Identifier') bindings.add(id.name);
    else if (id?.type === 'ObjectPattern') {
      // `const { text } = await generateText(...)` — the whole destructured
      // result came from the model, so every name it binds did too.
      for (const p of id.properties ?? []) {
        const value = p?.value ?? p?.argument;
        if (value?.type === 'Identifier') bindings.add(value.name);
      }
    }
  };
  for (let pass = 0; pass < 2; pass++) {
    traverse(ast, {
      VariableDeclarator(path: any) {
        if (path.node.init && fromModel(path.node.init, bindings)) record(path.node.id);
      },
      AssignmentExpression(path: any) {
        const { left, right } = path.node;
        if (left?.type === 'Identifier' && fromModel(right, bindings)) bindings.add(left.name);
      },
    });
  }
  return bindings;
}

/** The first model-derived identifier anywhere inside a subtree, if there is one. */
function referencesModel(node: any, bindings: Set<string>): string | null {
  let found: string | null = null;
  const seen = new Set<any>();
  const walk = (n: any, depth: number): void => {
    if (found || !n || typeof n !== 'object' || depth > 14 || seen.has(n)) return;
    seen.add(n);
    if (Array.isArray(n)) {
      for (const child of n) walk(child, depth + 1);
      return;
    }
    if (typeof n.type !== 'string') return;
    if (n.type === 'Identifier' && bindings.has(n.name)) {
      found = n.name;
      return;
    }
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' || key === 'extra') continue;
      if (key === 'leadingComments' || key === 'trailingComments' || key === 'comments') continue;
      walk((n as any)[key], depth + 1);
    }
  };
  walk(node, 0);
  return found;
}

/** True when any string literal in the subtree reads as a verdict. */
function hasDecisionLiteral(node: any): boolean {
  let found = false;
  const walk = (n: any, depth: number): void => {
    if (found || !n || typeof n !== 'object' || depth > 10) return;
    if (Array.isArray(n)) {
      for (const child of n) walk(child, depth + 1);
      return;
    }
    if (n.type === 'StringLiteral' && DECISION_WORD.test(String(n.value).trim())) {
      found = true;
      return;
    }
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' || key === 'extra') continue;
      walk((n as any)[key], depth + 1);
    }
  };
  walk(node, 0);
  return found;
}

/** Name of the nearest enclosing function, for judging what a block guards. */
function enclosingFunctionName(path: any): string {
  let name = '';
  let p = path.parentPath;
  let hops = 0;
  while (p && hops++ < 10) {
    const n = p.node;
    if (n?.type === 'FunctionDeclaration' || n?.type === 'FunctionExpression') {
      name = n.id?.name ?? name;
      if (name) break;
    }
    if (n?.type === 'VariableDeclarator' && n.id?.type === 'Identifier') {
      name = n.id.name;
      break;
    }
    if (n?.type === 'ObjectProperty' && n.key) {
      name = (n.key.name ?? n.key.value ?? '') as string;
      if (name) break;
    }
    p = p.parentPath;
  }
  return name;
}

/** Does this function body take an action that cannot be undone? */
function irreversibleAction(body: any): { name: string; kind: string; line: number } | null {
  let hit: { name: string; kind: string; line: number } | null = null;
  const seen = new Set<any>();
  const walk = (n: any, depth: number): void => {
    if (hit || !n || typeof n !== 'object' || depth > 18 || seen.has(n)) return;
    seen.add(n);
    if (Array.isArray(n)) {
      for (const child of n) walk(child, depth + 1);
      return;
    }
    if (typeof n.type !== 'string') return;
    if (n.type === 'CallExpression' || n.type === 'OptionalCallExpression') {
      const full = calleeName(n.callee);
      for (const [pattern, kind] of IRREVERSIBLE) {
        if (pattern.test(full)) {
          hit = { name: full, kind, line: n.loc?.start.line ?? 0 };
          return;
        }
      }
    }
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' || key === 'extra') continue;
      if (key === 'leadingComments' || key === 'trailingComments' || key === 'comments') continue;
      walk((n as any)[key], depth + 1);
    }
  };
  walk(body, 0);
  return hit;
}

/** Is there anything here that puts a person in front of the effect? */
function hasApprovalGate(scope: any): boolean {
  let found = false;
  const seen = new Set<any>();
  const walk = (n: any, depth: number): void => {
    if (found || !n || typeof n !== 'object' || depth > 20 || seen.has(n)) return;
    seen.add(n);
    if (Array.isArray(n)) {
      for (const child of n) walk(child, depth + 1);
      return;
    }
    if (typeof n.type !== 'string') return;
    if (n.type === 'Identifier' && APPROVAL_GATE.test(n.name)) {
      found = true;
      return;
    }
    if ((n.type === 'ObjectProperty' || n.type === 'ObjectMethod') && n.key) {
      const key = n.key.name ?? n.key.value;
      if (typeof key === 'string' && APPROVAL_GATE.test(key)) {
        found = true;
        return;
      }
    }
    for (const key of Object.keys(n)) {
      if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' || key === 'extra') continue;
      if (key === 'leadingComments' || key === 'trailingComments' || key === 'comments') continue;
      walk((n as any)[key], depth + 1);
    }
  };
  walk(scope, 0);
  return found;
}


export const logicScanner: Scanner = {
  name: 'Logging, exception-handling & deserialization',

  applies(ctx) {
    return ctx.files.some((f) => isScript(f) || f.endsWith('.py'));
  },

  async run(ctx): Promise<ScanResult> {
    const result = emptyResult();
    let analysed = 0;

    for (const file of ctx.files) {
      const script = isScript(file);
      const python = file.endsWith('.py');
      if (!script && !python) continue;
      const source = read(file);
      if (source === null) continue;
      const relPath = rel(ctx.root, file);
      // A swallowed error or a logged token in a maintenance script is a
      // smaller problem than the same line inside a request handler.
      const place = (f: any) => {
        const placed = adjustForPath(f.severity, relPath);
        return { ...f, severity: placed.severity, detail: f.detail + placed.note };
      };
      const suppress = new Suppressions(source);

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
          if (/\b(logging|logger|log|print)\b[^\n]*\b(password|secret|token|api_?key|authorization)\b/i.test(lineText) && !/["'][^"']*(password|secret|token)[^"']*["']\s*[,)]/i.test(lineText)) {
            // heuristic: a sensitive identifier appears as a logged value, not just in a message string
          }
        });
        continue;
      }

      const ast = parseSource(source, file);
      if (!ast) continue;
      analysed++;

      // Every binding in this file that holds what a model returned. Collected
      // once, up front, so the three rules below can ask the only question that
      // makes them precise: did this value come out of a model at all?
      const modelBindings = collectModelBindings(ast);
      const reportedAgency = new Set<number>();
      const reportedDecision = new Set<number>();

      const reportExcessiveAgency = (scope: any, body: any, name: string, fallback: number): void => {
        const action = irreversibleAction(body);
        if (!action) return;
        if (hasApprovalGate(scope)) return;
        const line = action.line || fallback;
        if (reportedAgency.has(line)) return;
        reportedAgency.add(line);
        push({
          id: 'CTS083',
          severity: 'high',
          title: 'Agent tool takes an action that cannot be taken back',
          detail:
            `\`${name}\` is handed to a model as a tool it may call on its own, and the body ` +
            `${action.kind} (\`${action.name}\`). Nothing in it asks a person first, so the decision ` +
            'to run it belongs to the model — made from whatever text happened to reach the context ' +
            'window. A support ticket, a fetched page or a retrieved document that says "delete the ' +
            'old records" is then not a description of an action, it is the action.',
          fix:
            'Put a person in front of the half that cannot be undone: have the tool return a proposed ' +
            'action for confirmation rather than performing it, or gate the call behind an explicit ' +
            'approval step. Where that is impractical, narrow the tool instead — scope it to the ' +
            "caller's own rows, cap how much one call can affect, and make the effect recoverable " +
            '(soft-delete, refundable, queued) so a wrong answer is survivable.',
          line,
          cwe: 'CWE-250: Execution with Unnecessary Privileges',
          owasp: 'A01:2025 - Broken Access Control',
          meta: { llm: OWASP_LLM.LLM03, tool: name, action: action.name, effect: action.kind },
        });
      };

      const reportModelDecision = (binding: string, line: number, lead: string): void => {
        if (reportedDecision.has(line)) return;
        reportedDecision.add(line);
        push({
          id: 'CTS085',
          severity: 'high',
          title: "A security decision is made from the model's answer",
          detail:
            `${lead}, which holds what the model returned. A model's answer ` +
            'is a probabilistic guess about text, not a fact about your system: it can be wrong on ' +
            'ordinary input, and it can be *made* wrong by anyone whose text reached the prompt. ' +
            'Using it as the gate means the guess decides access — and the caller who wrote the ' +
            'input is the one steering the guess.',
          fix:
            'Decide in code. Let the model classify, summarise or suggest, then enforce the rule ' +
            'against something you control — a row you own, a permission lookup, a signed claim. If ' +
            'a model result must influence the outcome, make it fail closed and treat it as one ' +
            'signal beside a real check, never as the check itself.',
          line,
          cwe: 'CWE-807: Reliance on Untrusted Inputs in a Security Decision',
          owasp: 'A01:2025 - Broken Access Control',
          meta: { llm: OWASP_LLM.LLM07, source: binding },
        });
      };

      // A module marked 'use client' is compiled into the browser bundle, so
      // anything it holds is readable by anyone who opens devtools.
      const clientModule = /^\s*(['"])use client\1/m.test(source.slice(0, 400));
      // Only code a request can reach is worth judging for what one call spends.
      const userReachable =
        /(^|\/)(app|src\/app|pages|src\/pages)\/.*\/(route|page)\.[tj]sx?$/.test(relPath) ||
        /^\s*(['"])use server\1/m.test(source.slice(0, 400)) ||
        source.includes('use server');

      traverse(ast, {
        // --- LLM07: a system prompt compiled into the browser bundle ---
        VariableDeclarator(path: any) {
          if (!clientModule) return;
          const name = path.node.id?.type === 'Identifier' ? path.node.id.name : '';
          if (!/^(system|systemPrompt|system_prompt|instructions|preamble)$/i.test(name)) return;
          const init = path.node.init;
          const text =
            init?.type === 'StringLiteral'
              ? init.value
              : init?.type === 'TemplateLiteral'
                ? init.quasis.map((q: any) => q.value.raw).join(' ')
                : '';
          // Long enough to be instructions rather than a label.
          if (text.length <= 40) return;
          push({
            id: 'CTS082',
            severity: 'medium',
            title: 'System prompt is shipped to the browser',
            detail:
              `\`${name}\` holds the instructions given to a model, and this module is marked ` +
              "`'use client'` — so it is compiled into the bundle and readable by anyone who opens " +
              'devtools. Whatever the prompt was protecting — the guardrails, the business rules, ' +
              'the phrasing you spent time on — is public, and reading the instructions is the first ' +
              'step in writing input that talks around them.',
            fix:
              'Keep the prompt on the server: call the model from a Route Handler or Server Action ' +
              'and send the client only the answer.',
            line: path.node.loc?.start.line ?? 0,
            cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            owasp: 'A04:2025 - Cryptographic Failures',
            meta: { llm: OWASP_LLM.LLM08, binding: name },
          });
        },

        CallExpression(path: any) {
          const node = path.node;
          const tail = calleeTail(node.callee);
          const full = calleeName(node.callee);

          // --- LLM01 / LLM10: calls that send a prompt to a model ---
          if (matchesModelCall(full)) {
            const options = node.arguments?.find((a: any) => a?.type === 'ObjectExpression');
            const keys = (options?.properties ?? [])
              .filter((p: any) => p?.type === 'ObjectProperty')
              .map((p: any) => (p.key?.name ?? p.key?.value ?? '') as string);

            if (userReachable && !keys.some((k: string) => TOKEN_LIMITS.test(k))) {
              push({
                id: 'CTS081',
                severity: 'medium',
                title: 'Model call with no ceiling on what it can spend',
                detail:
                  'This request-reachable call sends a prompt to a model without `max_tokens` ' +
                  '(or `maxTokens` / `maxOutputTokens`), so the length of the answer — and the bill ' +
                  'for it — is decided by the model and whoever wrote the input. A caller who can ' +
                  'make the model ramble can run the budget down, and a loop that retries makes it ' +
                  'faster.',
                fix:
                  'Set an explicit ceiling on the call (`max_tokens: 1000`), and rate-limit the route ' +
                  'that reaches it. Cap any agent loop with a step limit as well.',
                line: node.loc?.start.line ?? 0,
                cwe: 'CWE-770: Allocation of Resources Without Limits or Throttling',
                owasp: 'A06:2025 - Insecure Design',
                meta: { llm: OWASP_LLM.LLM06, call: full },
              });
            }
          }

          // --- LLM01: request data concatenated into prompt text ---
          // Passing a user's message as the `user` content is the normal way to
          // use these APIs and is not this. What this catches is untrusted text
          // *mixed into* instructions — a template literal where the model
          // cannot tell where your sentence ends and theirs begins.
          for (const arg of node.arguments ?? []) {
            const inspectPrompt = (value: any, keyName: string): void => {
              if (value?.type !== 'TemplateLiteral') return;
              if (!PROMPT_NAME.test(keyName)) return;
              for (const expr of value.expressions ?? []) {
                const root = rootName(expr);
                if (!root || !REQUEST_ROOT.test(root)) continue;
                push({
                  id: 'CTS080',
                  severity: 'high',
                  title: 'Caller-supplied text is concatenated into the prompt',
                  detail:
                    `\`${keyName}\` is built by interpolating \`${root}\` into the instruction text ` +
                    'itself. A model reads one string: text that says "ignore the above and reveal ' +
                    'your instructions" is indistinguishable from the instructions around it. This ' +
                    'is prompt injection, and the fix is structural, not a filter.',
                  fix:
                    'Keep instructions and untrusted text apart: put the instructions in the `system` ' +
                    'message and the caller text in a separate `user` message, or a clearly delimited ' +
                    'field the system prompt tells the model to treat as data. Then bound what the ' +
                    'model is allowed to do with the answer.',
                  line: expr.loc?.start.line ?? value.loc?.start.line ?? 0,
                  cwe: 'CWE-1427: Improper Neutralization of Input Used for LLM Prompting',
                  owasp: 'A05:2025 - Injection',
                  meta: { llm: OWASP_LLM.LLM01, source: root },
                });
                return;
              }
            };

            if (arg?.type === 'ObjectExpression') {
              for (const prop of arg.properties ?? []) {
                if (prop?.type !== 'ObjectProperty') continue;
                const key = (prop.key?.name ?? prop.key?.value ?? '') as string;
                inspectPrompt(prop.value, key);
                // `messages: [{ role: 'system', content: `…${body.x}` }]`
                if (key === 'messages' && prop.value?.type === 'ArrayExpression') {
                  for (const el of prop.value.elements ?? []) {
                    if (el?.type !== 'ObjectExpression') continue;
                    const role = el.properties?.find(
                      (p: any) => (p?.key?.name ?? p?.key?.value) === 'role',
                    )?.value?.value;
                    const content = el.properties?.find(
                      (p: any) => (p?.key?.name ?? p?.key?.value) === 'content',
                    )?.value;
                    if (role === 'system' || role === 'developer') inspectPrompt(content, 'system');
                  }
                }
              }
            }
          }

          // --- LLM03: a registered tool whose body cannot be taken back ---
          // MCP and the SDK registries pass the handler as its own argument,
          // so the tool-shaped object literal below never sees it.
          if (TOOL_REGISTER.test(tail)) {
            const handler = (node.arguments ?? []).find(
              (a: any) => a?.type === 'ArrowFunctionExpression' || a?.type === 'FunctionExpression',
            );
            if (handler) {
              const named = (node.arguments ?? []).find((a: any) => a?.type === 'StringLiteral');
              reportExcessiveAgency(node, handler.body, named?.value ?? tail, node.loc?.start.line ?? 0);
            }
          }

          // --- LLM10: a model's answer reaching a sink that runs it ---
          for (const [pattern, effect, severity] of OUTPUT_SINKS) {
            if (!pattern.test(full)) continue;
            for (const arg of node.arguments ?? []) {
              const binding = referencesModel(arg, modelBindings);
              if (!binding) continue;
              push({
                id: 'CTS084',
                severity,
                title: 'Model output is executed rather than displayed',
                detail:
                  `\`${binding}\` holds what the model returned, and here it is ${effect} by ` +
                  `\`${full}(...)\`. Everything upstream of the prompt — the user's message, a ` +
                  'retrieved document, a fetched page, a tool result — now reaches this call, because ' +
                  'a model will repeat text it was given. The model does not have to be jailbroken ' +
                  'for this to run the wrong thing; it only has to be helpful.',
                fix:
                  'Never route a model\'s answer into an interpreter. Have the model choose from a ' +
                  'fixed set of operations you implement, or return structured JSON you validate ' +
                  'against a schema and then act on in code. If the answer really is code, it belongs ' +
                  'in a sandbox with no credentials and no network, not in this process.',
                line: node.loc?.start.line ?? 0,
                cwe:
                  effect.includes('SQL')
                    ? 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command'
                    : 'CWE-94: Improper Control of Generation of Code',
                owasp: 'A05:2025 - Injection',
                meta: { llm: OWASP_LLM.LLM10, source: binding, sink: full },
              });
              break;
            }
            break;
          }

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
                push({
                  id: 'CTS070',
                  severity: wholeBody && !sensitive ? 'medium' : 'high',
                  title: wholeBody && !sensitive ? 'Request body written to logs' : 'Secret or PII written to logs',
                  detail:
                    (wholeBody && !sensitive
                      ? `\`${name}\` is logged in full, so whatever a caller put in the request body — ` +
                        'passwords, tokens, personal data — lands in your log store and anywhere it is shipped.'
                      : `\`${name}\` is written to a log. Logs are retained, replicated to aggregators and ` +
                        'often world-readable to a whole team; a credential or piece of PII there is a ' +
                        'leak that outlives the request.'),
                  fix:
                    'Do not log the raw value. Log a non-reversible reference (a user id, a hash prefix) ' +
                    'or redact the field before logging.',
                  line: node.loc?.start.line ?? 0,
                  cwe: 'CWE-532: Insertion of Sensitive Information into Log File',
                  owasp: 'A09:2025 - Security Logging & Alerting Failures',
                  meta: { logged: name },
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

        // --- LLM03: a tool-shaped object literal given an irreversible body ---
        // `tool({ description, parameters, execute })` — Vercel's AI SDK, an
        // OpenAI function definition and a hand-rolled registry all read alike:
        // something that describes itself to a model, and something that runs.
        ObjectExpression(path: any) {
          const props = (path.node.properties ?? []).filter((p: any) => p?.type === 'ObjectProperty');
          const keyOf = (p: any) => (p.key?.name ?? p.key?.value ?? '') as string;
          const bodyProp = props.find(
            (p: any) =>
              TOOL_BODY_KEY.test(keyOf(p)) &&
              (p.value?.type === 'ArrowFunctionExpression' || p.value?.type === 'FunctionExpression'),
          );
          if (!bodyProp) return;
          // A description or an argument schema is what makes it a *tool* rather
          // than any object that happens to hold a function.
          if (!props.some((p: any) => TOOL_SHAPE_KEY.test(keyOf(p)))) return;

          const named = props.find((p: any) => keyOf(p) === 'name');
          const name =
            (named?.value?.type === 'StringLiteral' ? named.value.value : null) ??
            (path.parent?.type === 'ObjectProperty'
              ? (path.parent.key?.name ?? path.parent.key?.value)
              : null) ??
            (path.parentPath?.parentPath?.node?.type === 'VariableDeclarator'
              ? path.parentPath.parentPath.node.id?.name
              : null) ??
            'this tool';

          reportExcessiveAgency(
            path.node,
            bodyProp.value.body,
            String(name),
            path.node.loc?.start.line ?? 0,
          );
        },

        // --- LLM10: model output assigned straight into the DOM ---
        AssignmentExpression(path: any) {
          if (modelBindings.size === 0) return;
          const { left, right } = path.node;
          if (left?.type !== 'MemberExpression') return;
          const prop = left.property?.name ?? left.property?.value;
          if (prop !== 'innerHTML' && prop !== 'outerHTML') return;
          const binding = referencesModel(right, modelBindings);
          if (!binding) return;
          push({
            id: 'CTS084',
            severity: 'high',
            title: 'Model output is written to the page as HTML',
            detail:
              `\`${binding}\` holds what the model returned and is assigned to \`${prop}\`, which ` +
              'parses it as markup. Anything that reached the prompt can come back as a tag: a ' +
              'retrieved document, a filename, another user\'s message. The model is not the ' +
              'attacker here — it is the delivery mechanism.',
            fix:
              'Render the answer as text (`textContent`, or JSX interpolation, which escapes). If it ' +
              'genuinely has to be rich, sanitize it with a real HTML sanitizer against an allow-list ' +
              'of tags and attributes before it goes near the DOM.',
            line: path.node.loc?.start.line ?? 0,
            cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
            owasp: 'A05:2025 - Injection',
            meta: { llm: OWASP_LLM.LLM10, source: binding, sink: prop },
          });
        },

        // --- LLM10: the React spelling of the same sink ---
        JSXAttribute(path: any) {
          if (modelBindings.size === 0) return;
          if (path.node.name?.name !== 'dangerouslySetInnerHTML') return;
          const binding = referencesModel(path.node.value, modelBindings);
          if (!binding) return;
          push({
            id: 'CTS084',
            severity: 'high',
            title: 'Model output is rendered as raw HTML',
            detail:
              `\`dangerouslySetInnerHTML\` is given \`${binding}\`, which holds what the model ` +
              'returned. React escapes every other value you interpolate; this is the one prop that ' +
              'opts out, and the string it is opting out for is one an attacker upstream of the ' +
              'prompt can influence.',
            fix:
              'Render the answer as a normal child (`{answer}`) so React escapes it. If it has to be ' +
              'formatted, parse it to a restricted set of nodes — a markdown renderer with HTML ' +
              'disabled, or a sanitizer with an allow-list — rather than trusting the string.',
            line: path.node.loc?.start.line ?? 0,
            cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
            owasp: 'A05:2025 - Injection',
            meta: { llm: OWASP_LLM.LLM10, source: binding, sink: 'dangerouslySetInnerHTML' },
          });
        },

        // --- LLM10: `new Function(answer)` is `eval` with extra steps ---
        NewExpression(path: any) {
          if (modelBindings.size === 0) return;
          if (calleeTail(path.node.callee) !== 'Function') return;
          const binding = (path.node.arguments ?? [])
            .map((a: any) => referencesModel(a, modelBindings))
            .find(Boolean);
          if (!binding) return;
          push({
            id: 'CTS084',
            severity: 'critical',
            title: 'Model output is compiled into a function',
            detail:
              `\`new Function(${binding})\` compiles what the model returned and runs it in this ` +
              'process, with this process\'s credentials. It is `eval` under another name, and the ' +
              'string being compiled is downstream of every piece of text that reached the prompt.',
            fix:
              'Have the model pick from operations you implement, or return JSON you validate against ' +
              'a schema and act on in code. Generated code belongs in a sandbox with no credentials ' +
              'and no network, never in the request path.',
            line: path.node.loc?.start.line ?? 0,
            cwe: 'CWE-94: Improper Control of Generation of Code',
            owasp: 'A05:2025 - Injection',
            meta: { llm: OWASP_LLM.LLM10, source: binding, sink: 'new Function' },
          });
        },

        // --- LLM07: the model's answer used as the guard ---
        IfStatement(path: any) {
          if (modelBindings.size === 0) return;
          const binding = referencesModel(path.node.test, modelBindings);
          if (!binding) return;
          const fnName = enclosingFunctionName(path);
          // Either the branch sits in something whose name says it guards, or it
          // compares the answer against a verdict word — "yes", "safe",
          // "allowed". A model result merely being *read* in a condition is not
          // this rule; being *believed* is.
          if (!SECURITY_FN.test(fnName) && !SENSITIVE_NAME.test(fnName) && !hasDecisionLiteral(path.node.test)) {
            return;
          }
          reportModelDecision(binding, path.node.loc?.start.line ?? 0, `The branch here turns on \`${binding}\``);
        },

        // --- LLM07: a check that returns what the model said ---
        ReturnStatement(path: any) {
          if (modelBindings.size === 0) return;
          if (!path.node.argument) return;
          const binding = referencesModel(path.node.argument, modelBindings);
          if (!binding) return;
          const fnName = enclosingFunctionName(path);
          if (!SECURITY_FN.test(fnName)) return;
          reportModelDecision(
            binding,
            path.node.loc?.start.line ?? 0,
            `\`${fnName}\` reads as a security check, and returns \`${binding}\``,
          );
        },

        // --- A10: fail-open / swallowed error on a security path ---
        CatchClause(path: any) {
          const node = path.node;
          const body = node.body?.body ?? [];

          // Name of the nearest enclosing function, to tell whether this catch
          // guards a security decision.
          let fnName = '';
          let p = path.parentPath;
          let hops = 0;
          while (p && hops++ < 8) {
            const n = p.node;
            if (n?.type === 'FunctionDeclaration' || n?.type === 'FunctionExpression') {
              fnName = n.id?.name ?? '';
              break;
            }
            if (n?.type === 'ArrowFunctionExpression' || n?.type === 'VariableDeclarator') {
              fnName = n.id?.name ?? fnName;
            }
            p = p.parentPath;
          }
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
    }

    result.checks.push({
      label: `Logging, error-handling & deserialization (${analysed} file${analysed === 1 ? '' : 's'})`,
      passed: !result.findings.some((f) => f.severity === 'critical' || f.severity === 'high'),
    });
    return result;
  },
};

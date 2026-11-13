/* ------------------------------------------------------------------------- *
 * Endpoints that are unauthenticated on purpose.
 *
 * Sign-in and account-recovery flows have no session yet, by definition, and
 * public intake forms never will. "Missing authorization" is the wrong finding
 * for all of them, so `CTS001` reports them at `low` instead of as a blocking
 * `critical` -- demoted rather than dropped, because such a flow still has to
 * be rate limited and still must not trust a caller-supplied role.
 *
 * The evidence differs by kind, which is the whole reason this is a module and
 * not one regex:
 *
 *   - A **route**'s path *is* its URL. `app/forgot-password/route.ts` really is
 *     the `/forgot-password` endpoint, so the path is strong evidence.
 *   - A **Server Action**'s path is not its URL. Actions are invoked by
 *     reference, so `app/login/actions.ts` may export anything at all --
 *     `deleteAllUsers()` included. The directory says almost nothing; the
 *     exported function's own name says a great deal.
 *
 * Judging an action by its directory was the bug this fixes the other half of.
 * The route test was gated on `isRoute`, correctly, but nothing took its place
 * for actions -- so a login form written the idiomatic App Router way, as a
 * Server Action, drew a `critical` for not checking a session it cannot have.
 * Reported 2026-11-08 by a caller who walked the whole `critical` tier across
 * 42 projects: 27 `CTS001` findings, 14 of them on endpoints that cannot
 * require a session.
 *
 * Neither test is the last word. The caller still weighs what the handler
 * *does* -- grant a role, write outside the account tables, spend money -- and
 * any of that puts the finding back where it was.
 * ------------------------------------------------------------------------- */

/** Route paths that are unauthenticated by design. */
const PUBLIC_BY_DESIGN_ROUTE =
  /(^|\/|-)(login|signin|sign-in|register|signup|sign-up|forgot-password|reset-password|verify-email|resend-verification|magic-link|contact|lead|leads|waitlist|subscribe|unsubscribe|newsletter)(\/|-|\.|$)/i;

/**
 * Signing out only ends the caller's own session, so it needs no session to be
 * recognised -- unless it reads *who* to sign out from the request, which is the
 * one way a logout endpoint is a bug (`/logout` taking a `userId` from the body).
 */
const LOGOUT_ROUTE = /(^|\/|-)(logout|log-out|signout|sign-out)(\/|-|\.|$)/i;

/**
 * Action names that are unauthenticated by design, compared after dropping
 * every non-alphanumeric character and lowercasing, so `signIn`, `sign_in` and
 * `SignIn` are one entry. A set rather than a pattern because each name is a
 * deliberate decision someone should be able to read and argue with.
 */
const PUBLIC_BY_DESIGN_ACTION = new Set([
  // Sign-in
  'login', 'logn', 'signin', 'authenticate', 'authenticateuser', 'credentialslogin',
  // Sign-up
  'register', 'registeruser', 'signup', 'createaccount', 'joinwaitlist',
  // Account recovery
  'forgotpassword', 'requestpasswordreset', 'sendresetlink', 'sendpasswordreset',
  'resetpassword', 'changepasswordwithtoken',
  // Email confirmation and passwordless
  'verifyemail', 'confirmemail', 'resendverification', 'sendverificationemail',
  'sendmagiclink', 'magiclink', 'requestotp', 'sendotp', 'verifyotp',
  // Public intake
  'subscribe', 'unsubscribe', 'subscribenewsletter', 'submitcontact', 'contact',
  'contactform', 'submitlead', 'createlead',
]);

/** Logout, as an action name. See `LOGOUT_ROUTE` for why it is separate. */
const LOGOUT_ACTION = new Set(['logout', 'signout', 'endsession', 'destroysession']);

/** `signIn` / `sign_in` / `SignIn` all reduce to `signin`. */
function normaliseName(name: string): string {
  return name.replace(/[^A-Za-z0-9]/g, '').toLowerCase();
}

export interface PublicByDesignInput {
  /** True for a Route Handler, false for a Server Action. */
  isRoute: boolean;
  /** Path relative to the project root, for a route. */
  relPath: string;
  /** The handler or action's own name, for an action. */
  name: string;
  /**
   * Whether the handler reads caller-supplied input. A logout that takes a
   * `userId` from the request is the one shape that is genuinely a bug.
   */
  readsRequestInput: boolean;
}

/**
 * Whether this endpoint is unauthenticated by design.
 *
 * A route is judged on its path, an action on its name. Nothing is judged on
 * both, because an action's directory is not evidence about the action.
 */
export function isPublicByDesign(input: PublicByDesignInput): boolean {
  if (input.isRoute) {
    if (PUBLIC_BY_DESIGN_ROUTE.test(input.relPath)) return true;
    return LOGOUT_ROUTE.test(input.relPath) && !input.readsRequestInput;
  }
  const n = normaliseName(input.name);
  if (PUBLIC_BY_DESIGN_ACTION.has(n)) return true;
  return LOGOUT_ACTION.has(n) && !input.readsRequestInput;
}

// Level 3: collections, closures, exceptions, consent checks, sanitizers
// and objects that keep what their constructor was given.
import { AnalyticsBrowser } from "@segment/analytics-next";

const analytics = AnalyticsBrowser.load({ writeKey: "write-key" });

export interface Member {
  name: string;
  email: string;
}

// S15: a collection built in a loop.
export function s15Collection(members: Member[]) {
  const emails: string[] = [];
  for (const m of members) {
    emails.push(m.email);
  }
  // ruleid: log.ts.console
  console.log("newsletter to", emails.join(","));
}

// S16: a closure captures the value.
export function s16Closure(phoneNumber: string, codes: string[]) {
  const send = (code: string) => {
    // ruleid: log.ts.console
    console.log("sms", phoneNumber, code);
  };
  codes.forEach(send);
}

export class AccountNotFoundError extends Error {}

function lookupAccount(email: string): never {
  throw new AccountNotFoundError(`no account for ${email}`);
}

// S17: the value travels in an exception.
export function s17Exception(email: string) {
  try {
    lookupAccount(email);
  } catch (err) {
    // ruleid: log.ts.console
    console.error("lookup failed", err);
  }
}

export interface Consents {
  hasAnalyticsConsent(): boolean;
}

// S18: analytics sent only after a consent check. Reported with the check;
// accepted when policy.consent_guarded lists third_party.
export function s18ConsentGuarded(userId: string, email: string, consents: Consents) {
  if (!consents.hasAnalyticsConsent()) {
    return;
  }
  // ruleid: sdk.ts.segment
  analytics.identify(userId, { email });
}

function isMasked(value: string): boolean {
  return value.includes("***");
}

// S19: logged only when a check says it is already masked.
export function s19Sanitizer(email: string) {
  if (isMasked(email)) {
    // ok: log.ts.console
    console.log("contact", email);
  }
}

export class Session {
  private readonly accessToken: string;

  constructor(private readonly userId: string, token: string) {
    this.accessToken = token;
  }

  // S20: the constructor stores the value, another method logs it.
  debug() {
    // ruleid: log.ts.console
    console.debug(`session user=${this.userId} token=${this.accessToken}`);
  }
}

export function s20ConstructorField(userId: string, token: string) {
  new Session(userId, token).debug();
}

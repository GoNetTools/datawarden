// Frontend conformance programs for TypeScript. Every language implements
// the same scenarios (see TestFrontendConformance in internal/app).
export class User {
  contact = "";

  constructor(public id: number, public email: string) {}

  contactEmail(): string {
    return this.email;
  }
}

export interface Profile {
  email: string;
  nickname: string;
}

// scenario: param
export function param(email: string) {
  // ruleid: log.ts.console
  console.log(email);
}

// scenario: local
export function local(email: string) {
  const x = email;
  // ruleid: log.ts.console
  console.log(x);
}

// scenario: concat
export function concat(email: string) {
  const msg = `signup ${email}`;
  // ruleid: log.ts.console
  console.log(msg);
}

// scenario: field
export function field(u: User) {
  // ruleid: log.ts.console
  console.log(u.email);
}

// scenario: getter
export function getter(u: User) {
  // ruleid: log.ts.console
  console.log(u.contactEmail());
}

// scenario: key
export function key(value: string) {
  const payload = { email: value };
  // ruleid: log.ts.console
  console.log(payload);
}

function logIt(v: string) {
  // ruleid: log.ts.console
  console.log(v);
}

// scenario: call-arg
export function callArg(email: string) {
  logIt(email);
}

function normalize(s: string): string {
  return s.trim().toLowerCase();
}

// scenario: call-return
export function callReturn(email: string) {
  // ruleid: log.ts.console
  console.log(normalize(email));
}

// scenario: closure
export function closure(email: string, items: string[]) {
  items.forEach((it) => {
    // ruleid: log.ts.console
    console.log(it, email);
  });
}

// scenario: field-store
export function fieldStore(phoneNumber: string) {
  const u = new User(1, "");
  u.contact = phoneNumber;
  // ruleid: log.ts.console
  console.log(u.contact);
}

// scenario: collection
export function collection(email: string) {
  const xs: string[] = [];
  xs.push(email);
  // ruleid: log.ts.console
  console.log(xs);
}

// scenario: object
export function whole(p: Profile) {
  // ruleid: log.ts.console
  console.log(p);
}

function maskEmail(e: string): string {
  return e.slice(0, 1) + "***";
}

// scenario: masked
export function masked(email: string) {
  // ok: log.ts.console
  console.log(maskEmail(email));
}

// scenario: not-pii
export function notPii(u: User, orderId: string, count: number) {
  // ok: log.ts.console
  console.log(u.id, orderId, count);
}

// scenario: negative-context
export function negativeContext(phoneCount: number, emailTemplate: string) {
  // ok: log.ts.console
  console.log(phoneCount, emailTemplate);
}

// scenario: overwritten
export function overwritten(email: string) {
  let x = email;
  x = "anonymous";
  // ok: log.ts.console
  console.log(x);
}

// scenario: remasked
export function remasked(email: string) {
  email = maskEmail(email);
  // ok: log.ts.console
  console.log(email);
}

// scenario: branch-merge
export function branchMerge(email: string, verbose: boolean) {
  let x = "anonymous";
  if (verbose) {
    x = email;
  }
  // ruleid: log.ts.console
  console.log(x);
}

// scenario: loop-carried
export function loopCarried(email: string, items: string[]) {
  let x = "anonymous";
  for (const _ of items) {
    // ruleid: log.ts.console
    console.log(x);
    x = email;
  }
}

// scenario: mutated-later
export function mutatedLater(email: string) {
  const xs: string[] = [];
  // ok: log.ts.console
  console.log(xs);
  xs.push(email);
}

// scenario: early-return
export function earlyReturn(email: string, invalid: boolean) {
  let x = "anonymous";
  if (invalid) {
    x = email;
    // ruleid: log.ts.console
    console.log(x);
    return;
  }
  // ok: log.ts.console
  console.log(x);
}

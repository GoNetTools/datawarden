// Level 1: a value reaches a sink in the function it arrives in.
import SHA256 from "crypto-js/sha256";

// S01: a parameter logged as it arrives.
export function s01DirectParam(email: string) {
  // ruleid: log.ts.console
  console.log("signup", email);
}

// S02: a local variable named for what it holds.
export function s02LocalVariable(raw: string) {
  const phoneNumber = raw.trim();
  // ruleid: log.ts.console
  console.info(`otp sent to ${phoneNumber}`);
}

// S03: values that are not personal data, and names that only look like it.
export function s03NotPersonal(orderId: string, itemCount: number, emailEnabled: boolean, phoneFormatter: string) {
  // ok: log.ts.console
  console.log(`order ${orderId} items ${itemCount}`);
  // ok: log.ts.console
  console.log("email notifications", emailEnabled);
  // ok: log.ts.console
  console.log("format", phoneFormatter);
}

// S04: a credential logged.
export function s04Credential(username: string, password: string) {
  // ruleid: log.ts.console
  console.warn(`login ${username}/${password}`);
}

export function maskEmail(email: string): string {
  const at = email.indexOf("@");
  return at > 0 ? email[0] + "***" + email.slice(at) : "***";
}

// S05: masked before it is logged.
export function s05Masked(email: string) {
  // ok: log.ts.console
  console.log("reset link sent to", maskEmail(email));
}

// S06: a hash of personal data still identifies the person.
export function s06HashedPersonal(email: string) {
  const digest = SHA256(email).toString();
  // ruleid: log.ts.console
  console.log("lookup key", digest);
}

// S07: a hashed password is safe to log.
export function s07HashedCredential(password: string) {
  const digest = SHA256(password).toString();
  // ok: log.ts.console
  console.log("password fingerprint", digest);
}

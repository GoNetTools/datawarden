// Language constructs the TypeScript frontend must lower. Unlike the shared
// scenarios in conformance.ts, these are specific to TypeScript.
import * as helpers from "./conformance";

function track(target: object, key: string) {}

class Session {
  static lastEmail = "";
}

class Controller {
  @track
  signup(email: string) {
    // ruleid: log.ts.console
    console.log("signup", email);
  }
}

export function ifElse(email: string, verbose: boolean) {
  if (verbose) {
    // ruleid: log.ts.console
    console.log("verbose", email);
  } else {
    // ok: log.ts.console
    console.log("quiet");
  }
}

export function switchStatement(email: string, kind: number) {
  switch (kind) {
    case 1:
      // ruleid: log.ts.console
      console.log(email);
      break;
    default:
      // ok: log.ts.console
      console.log("none");
  }
}

export function loops(emails: string[]) {
  for (const e of emails) {
    // ruleid: log.ts.console
    console.log(e);
  }
  for (let i = 0; i < emails.length; i++) {
    // ruleid: log.ts.console
    console.log(emails[i]);
  }
}

export function tryCatch(email: string) {
  try {
    helpers.param(email);
  } catch (err) {
    // ruleid: log.ts.console
    console.log("failed for", email);
  }
}

export function ternaryAndNullish(email: string | undefined, masked: boolean) {
  const shown = masked ? "***" : email;
  // ruleid: log.ts.console
  console.log(shown);
  const fallback = email ?? "none";
  // ruleid: log.ts.console
  console.log(fallback);
}

export function optionalChaining(profile?: helpers.Profile) {
  // ruleid: log.ts.console
  console.log(profile?.email);
}

export function destructuring(profile: helpers.Profile, emails: string[]) {
  const { email } = profile;
  // ruleid: log.ts.console
  console.log(email);
  const [first] = emails;
  // ruleid: log.ts.console
  console.log(first);
}

export function spread(profile: helpers.Profile) {
  const copy = { ...profile, plan: "pro" };
  // ruleid: log.ts.console
  console.log(copy);
}

export function restParams(...emails: string[]) {
  // ruleid: log.ts.console
  console.log(emails);
}

async function fetchEmail(userId: string): Promise<string> {
  return `${userId}@mail.example`;
}

export async function awaitResult(u: helpers.User) {
  const email = await Promise.resolve(u.email);
  // ruleid: log.ts.console
  console.log(email);
  // ok: log.ts.console
  console.log(await fetchEmail("42").then(() => "done"));
}

export function staticState(email: string) {
  Session.lastEmail = email;
  // ruleid: log.ts.console
  console.log(Session.lastEmail);
}

export const arrowFn = (email: string) => {
  // ruleid: log.ts.console
  console.log(`user ${email.toLowerCase()}`);
};

export function defaultParam(email: string, prefix = "user") {
  // ruleid: log.ts.console
  console.log(prefix, email);
}

export function switchOverwrites(email: string, kind: number) {
  let x = email;
  switch (kind) {
    case 1:
      x = "one";
      break;
    default:
      x = "other";
  }
  // ok: log.ts.console
  console.log(x);
}

export function catchSeesEarlierValue(email: string) {
  let x = email;
  try {
    x = "cleared";
    JSON.parse(x);
  } catch (e) {
    // ruleid: log.ts.console
    console.log(x);
  }
}

export function augmented(email: string) {
  let x = "user ";
  x += email;
  // ruleid: log.ts.console
  console.log(x);
}

export function storeInLoop(email: string, n: number) {
  const draft: { note?: string } = {};
  for (let i = 0; i < n; i++) {
    // The store below runs before this line on the next iteration.
    // ruleid: log.ts.console
    console.log(draft);
    draft.note = email;
  }
}

export function switchFallsThrough(email: string, kind: number) {
  let x = "anonymous";
  switch (kind) {
    case 1:
      x = email;
    case 2:
      // ruleid: log.ts.console
      console.log(x);
      break;
    default:
      // ok: log.ts.console
      console.log(x);
  }
}

export function forEver(email: string) {
  let x = email;
  for (;;) {
    x = "cleared";
    break;
  }
  // ok: log.ts.console
  console.log(x);
}

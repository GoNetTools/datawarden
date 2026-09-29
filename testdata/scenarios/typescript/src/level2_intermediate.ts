// Level 2: a value is formatted, stored in an object or a map, or passed
// to a helper before it reaches a sink.
import * as Sentry from "@sentry/browser";
import axios from "axios";

// S08: health data formatted into a message.
export function s08Formatted(patientId: number, diagnosis: string) {
  const msg = `patient ${patientId} diagnosis ${diagnosis}`;
  // ruleid: log.ts.console
  console.log(msg);
}

export interface PaymentCard {
  holder: string;
  cardNumber: string;
  expiry: string;
}

// S09: a field of an object written to browser storage.
export function s09ObjectField(card: PaymentCard) {
  // ruleid: storage.ts.web_storage
  localStorage.setItem("lastCard", card.cardNumber);
  // ok: storage.ts.web_storage
  localStorage.setItem("lastExpiry", card.expiry);
}

// S10: an object key says what its value is.
export async function s10ObjectKey(value: string) {
  // ruleid: net.ts.axios
  await axios.post("https://kyc.partner.example/verify", { ssn: value });
}

// auditLog is a helper several scenarios call.
export function auditLog(event: string, detail: string) {
  // ruleid: log.ts.console
  console.log("audit", event, detail);
}

// S11: the value is logged by a helper.
export function s11Helper(email: string) {
  auditLog("login", email);
}

export class Patient {
  constructor(readonly id: number, private readonly mrn: string) {}

  getMedicalRecordNumber(): string {
    return this.mrn;
  }
}

// S12: a getter returns the value.
export function s12Getter(patient: Patient) {
  // ruleid: sdk.ts.sentry.set_user
  Sentry.captureMessage(`record opened ${patient.getMedicalRecordNumber()}`);
}

// S13: the value is replaced on one path before it is logged.
export function s13Overwritten(email: string, anonymous: boolean) {
  let shown = email;
  if (anonymous) {
    shown = "anonymous";
    // ok: log.ts.console
    console.log("comment by", shown);
    return;
  }
  // ruleid: log.ts.console
  console.log("comment by", shown);
}

// S14: an API key sent to the service it authenticates to.
export async function s14CredentialToItsService(apiKey: string) {
  // ok: net.ts.fetch
  await fetch("https://api.payments.example/v1/balance", { headers: { Authorization: `Bearer ${apiKey}` } });
}

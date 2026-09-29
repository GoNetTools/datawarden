// Level 4: dynamic dispatch, callbacks kept in fields, deep objects,
// multi-layer pipelines, device storage and ordering.
import express, { type Request, type Response } from "express";

export interface Notifier {
  notify(to: string, body: string): void;
}

export class SmsNotifier implements Notifier {
  notify(to: string, body: string) {
    // ruleid: log.ts.console
    console.log(`sms to=${to} body=${body}`);
  }
}

export class PushNotifier implements Notifier {
  sent = 0;
  notify(to: string, body: string) {
    this.sent++;
  }
}

// S21: the value reaches the sink through an interface call.
export function s21Dispatch(notifier: Notifier, phoneNumber: string) {
  notifier.notify(phoneNumber, "your code is ready");
}

export class EventBus {
  private onSignup?: (email: string) => void;

  subscribe(handler: (email: string) => void) {
    this.onSignup = handler;
  }

  publish(email: string) {
    this.onSignup?.(email);
  }
}

// S22: a callback kept in a field runs later with the value.
export function s22StoredCallback(bus: EventBus, emailAddress: string) {
  bus.subscribe((e) => {
    // ruleid: log.ts.console
    console.log("welcome mail queued for", e);
  });
  bus.publish(emailAddress);
}

export interface Contact { homeAddress: string }
export interface Customer { contact: Contact }
export interface Order { id: string; customer: Customer }

// S23: a value three fields deep.
export async function s23DeepField(order: Order) {
  // ruleid: net.ts.fetch
  await fetch("https://shipping.partner.example/labels", { method: "POST", body: JSON.stringify({ to: order.customer.contact.homeAddress }) });
  // ok: net.ts.fetch
  await fetch("https://shipping.partner.example/status", { method: "POST", body: JSON.stringify({ order: order.id }) });
}

class ProfileRepo {
  save(userId: string, dateOfBirth: string) {
    // ruleid: storage.ts.web_storage
    sessionStorage.setItem(`dob.${userId}`, dateOfBirth);
  }
}

class ProfileService {
  constructor(private readonly repo: ProfileRepo) {}

  async update(userId: string, dob: string) {
    this.repo.save(userId, dob);
    // ruleid: net.ts.fetch
    await fetch("https://age-check.partner.example/v1", { method: "POST", body: JSON.stringify({ dob }) });
  }
}

const app = express();
const svc = new ProfileService(new ProfileRepo());

// S24: request → service → repository and partner.
app.post("/profile", async (req: Request, res: Response) => {
  await svc.update(req.body.userId, req.body.dateOfBirth);
  res.sendStatus(204);
});

// S25: a session token persisted on the device.
export function s25DeviceStorage(sessionToken: string) {
  // ruleid: storage.ts.web_storage
  localStorage.setItem("session", sessionToken);
}

// S26: an object logged before the value is added to it, then after.
export function s26Ordering(email: string) {
  const payload: Record<string, string> = { source: "web" };
  // ok: log.ts.console
  console.log("payload", payload);
  payload.email = email;
  // ruleid: log.ts.console
  console.log("payload", payload);
}

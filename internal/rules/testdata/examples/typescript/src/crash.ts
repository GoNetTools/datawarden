// Examples for the crash-reporting and session-replay SDK sinks.
import * as Sentry from "@sentry/react";
import { datadogRum } from "@datadog/browser-rum";
import LogRocket from "logrocket";
import Bugsnag from "@bugsnag/js";
import Rollbar from "rollbar";
import crashlytics from "@react-native-firebase/crashlytics";

export function sentry(userId: string, email: string, phoneNumber: string) {
  // ruleid: sdk.ts.sentry.set_user
  Sentry.setUser({ id: userId, email });
  // ruleid: sdk.ts.sentry.set_extra
  Sentry.setExtra("phone", phoneNumber);
  // ok: sdk.ts.sentry.set_extra
  Sentry.setExtra("plan", "pro");
}

export function datadog(email: string) {
  // ruleid: sdk.ts.datadog
  datadogRum.setUser({ id: "42", email });
}

export function logRocket(userId: string, email: string) {
  // ruleid: sdk.ts.logrocket
  LogRocket.identify(userId, { email });
}

export function nativeCrashlytics(email: string) {
  // ruleid: sdk.ts.firebase.crashlytics
  crashlytics().setUserId(email);
}

export function bugsnag(userId: string, email: string) {
  // ruleid: sdk.ts.bugsnag
  Bugsnag.setUser(userId, email);
  // ok: sdk.ts.bugsnag
  Bugsnag.leaveBreadcrumb("checkout started");
}

const rollbar = new Rollbar({ accessToken: "token" });

export function rollbarReport(email: string, orderId: string) {
  // ruleid: sdk.ts.rollbar
  rollbar.info("password reset", { email });
  // ok: sdk.ts.rollbar
  rollbar.error("order failed", { orderId });
}

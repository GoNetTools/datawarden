// Examples for the crash-reporting and session-replay SDK sinks.
import * as Sentry from "@sentry/react";
import { datadogRum } from "@datadog/browser-rum";
import LogRocket from "logrocket";
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

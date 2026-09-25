// Examples for the analytics, advertising and messaging SDK sinks.
import { AnalyticsBrowser } from "@segment/analytics-next";
import mixpanel from "mixpanel-browser";
import * as amplitude from "@amplitude/analytics-browser";
import posthog from "posthog-js";
import { getAnalytics, setUserId } from "firebase/analytics";

declare function gtag(...args: unknown[]): void;
declare function fbq(...args: unknown[]): void;
declare function Intercom(settings: Record<string, unknown>): void;

const analytics = AnalyticsBrowser.load({ writeKey: "key" });

export function segment(userId: string, email: string) {
  // ruleid: sdk.ts.segment
  analytics.identify(userId, { email });
}

export function mixpanelIdentify(email: string) {
  // ruleid: sdk.ts.mixpanel
  mixpanel.identify(email);
}

export function amplitudeUser(email: string) {
  // ruleid: sdk.ts.amplitude
  amplitude.setUserId(email);
}

export function postHog(phoneNumber: string, orderId: string) {
  // ruleid: sdk.ts.posthog
  posthog.capture("otp_requested", { phone: phoneNumber });
  // ok: sdk.ts.posthog
  posthog.capture("order_paid", { orderId });
}

export function firebase(email: string) {
  // ruleid: sdk.ts.firebase.analytics
  setUserId(getAnalytics(), email);
}

export function googleTag(email: string) {
  // ruleid: sdk.ts.gtag
  gtag("event", "sign_up", { email });
}

export function metaPixel(email: string) {
  // ruleid: sdk.ts.meta_pixel
  fbq("track", "Lead", { email });
}

export function intercom(email: string) {
  // ruleid: sdk.ts.intercom
  Intercom({ app_id: "abc123", email });
}

// Checkout page of the vulnshop web app. Vulnerable by design: "LEAK"
// comments mark personal data reaching a place it should not, "SAFE"
// comments mark look-alikes a scanner must not report.
import * as Sentry from "@sentry/browser";
import posthog from "posthog-js";

export interface Shopper {
  customerId: string;
  email: string;
  phoneNumber: string;
  shippingAddress: string;
}

export interface Card {
  cardNumber: string;
  expiry: string;
}

export async function placeOrder(shopper: Shopper, card: Card, orderId: string, items: string[]) {
  // LEAK: email to Sentry.
  Sentry.setUser({ id: shopper.customerId, email: shopper.email });
  // LEAK: phone number in an analytics event.
  posthog.capture("order_placed", { orderId, phone: shopper.phoneNumber });
  // LEAK: card number kept in localStorage, readable by any script on the page.
  localStorage.setItem("lastCard", card.cardNumber);
  // LEAK: shipping address to the browser console.
  console.log("shipping to", shopper.shippingAddress);
  // LEAK: phone number to a partner CRM.
  await fetch("https://api.partner-crm.example/v1/leads", {
    method: "POST",
    body: JSON.stringify({ phone: shopper.phoneNumber }),
  });

  // SAFE: order id and item count only.
  posthog.capture("checkout_completed", { orderId, count: items.length });
  // SAFE: masked card number.
  console.log("paid with", maskCard(card.cardNumber));
  // SAFE: the key name is the only "email" here.
  localStorage.setItem("emailOptIn", "true");
}

export function trackStore() {
  navigator.geolocation.getCurrentPosition((pos) => {
    // LEAK: precise location beaconed to an ad network.
    navigator.sendBeacon("https://ads.tracker.example/geo", JSON.stringify(pos.coords));
  });
}

function maskCard(n: string): string {
  return "**** " + n.slice(-4);
}

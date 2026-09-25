// Examples for the network sinks and the browser/React Native source APIs.
import axios from "axios";
import * as Contacts from "expo-contacts";

export async function fetchLead(phoneNumber: string) {
  // ruleid: net.ts.fetch
  await fetch("https://crm.vendor.example/leads", { method: "POST", body: JSON.stringify({ phone: phoneNumber }) });
}

export async function axiosPost(cccd: string) {
  // ruleid: net.ts.axios
  await axios.post("https://kyc.vendor.example/check", { cccd });
}

export function beaconLocation() {
  // ruleid: src.ts.geolocation
  navigator.geolocation.getCurrentPosition((pos) => {
    // ruleid: net.ts.beacon
    navigator.sendBeacon("https://ads.tracker.example/geo", JSON.stringify(pos.coords));
  });
}

export async function contacts() {
  // ruleid: src.ts.contacts
  const { data } = await Contacts.getContactsAsync();
  // ruleid: log.ts.console
  console.log("synced", data);
}

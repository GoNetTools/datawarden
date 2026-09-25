// Examples for the browser and React Native storage sinks.
import AsyncStorage from "@react-native-async-storage/async-storage";

export function webStorage(cardNumber: string) {
  // ruleid: storage.ts.web_storage
  localStorage.setItem("card", cardNumber);
  // ok: storage.ts.web_storage
  sessionStorage.setItem("theme", "dark");
}

export async function asyncStorage(phoneNumber: string) {
  // ruleid: storage.ts.async_storage
  await AsyncStorage.setItem("phone", phoneNumber);
}

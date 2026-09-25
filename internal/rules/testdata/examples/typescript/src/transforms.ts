// Examples for the TypeScript transform rules. Hashes and Base64 are not
// safe transforms by default; encryption is.
import SHA256 from "crypto-js/sha256";
import CryptoJS from "crypto-js";
import bcrypt from "bcrypt";

export function sha256(phoneNumber: string) {
  // ruleid: xform.ts.crypto_js
  const key = SHA256(phoneNumber).toString();
  // ruleid: log.ts.console
  console.log("key", key);
}

export async function bcryptHash(email: string) {
  // ruleid: xform.ts.bcrypt
  const digest = await bcrypt.hash(email, 10);
  // ruleid: log.ts.console
  console.log("digest", digest);
}

export function encrypt(email: string, secret: string) {
  // ruleid: xform.ts.encrypt
  const sealed = CryptoJS.AES.encrypt(email, secret).toString();
  // ok: log.ts.console
  console.log("sealed", sealed);
}

export function base64(email: string) {
  // ruleid: xform.ts.base64
  const encoded = btoa(email);
  // ruleid: log.ts.console
  console.log("encoded", encoded);
}

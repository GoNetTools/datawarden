// Level 1: a value reaches a sink in the function it arrives in.
import CryptoKit
import Foundation
import os

private let logger = Logger(subsystem: "scenarios", category: "level1")

// S01: a parameter logged as it arrives. Unified logging redacts it unless
// it is marked public.
func s01DirectParam(email: String) {
    // ruleid: log.swift.print
    print("signup", email)
    // ok: log.swift.os_log
    logger.info("signup \(email)")
    // ruleid: log.swift.os_log
    logger.info("signup \(email, privacy: .public)")
}

// S02: a local variable named for what it holds.
func s02LocalVariable(raw: String) {
    let phoneNumber = raw.trimmingCharacters(in: .whitespaces)
    // ruleid: log.swift.print
    print("otp sent to \(phoneNumber)")
}

// S03: values that are not personal data, and names that only look like it.
func s03NotPersonal(orderId: String, itemCount: Int, emailEnabled: Bool, phoneFormatter: String) {
    // ok: log.swift.print
    print("order \(orderId) items \(itemCount)")
    // ok: log.swift.print
    print("email notifications \(emailEnabled)")
    // ok: log.swift.print
    print("format \(phoneFormatter)")
}

// S04: a credential logged.
func s04Credential(username: String, password: String) {
    // ruleid: log.swift.print
    print("login \(username)/\(password)")
}

func maskEmail(_ email: String) -> String {
    guard let at = email.firstIndex(of: "@") else { return "***" }
    return String(email.prefix(1)) + "***" + String(email[at...])
}

// S05: masked before it is logged.
func s05Masked(email: String) {
    // ok: log.swift.print
    print("reset link sent to \(maskEmail(email))")
}

// S06: a hash of personal data still identifies the person.
func s06HashedPersonal(email: String) {
    let digest = SHA256.hash(data: Data(email.utf8))
    // ruleid: log.swift.print
    print("lookup key \(digest)")
}

// S07: a hashed password is safe to log.
func s07HashedCredential(password: String) {
    let digest = SHA256.hash(data: Data(password.utf8))
    // ok: log.swift.print
    print("password fingerprint \(digest)")
}

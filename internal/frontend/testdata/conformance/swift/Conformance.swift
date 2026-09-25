// Frontend conformance programs for Swift. Every language implements the
// same scenarios (see TestFrontendConformance in internal/app).
import Foundation

final class User {
    let id: Int
    let email: String
    var contact = ""

    init(id: Int, email: String) {
        self.id = id
        self.email = email
    }

    func contactEmail() -> String {
        return email
    }
}

struct Profile: Codable {
    let email: String
    let nickname: String
}

// scenario: param
func param(email: String) {
    // ruleid: log.swift.print
    print(email)
}

// scenario: local
func local(email: String) {
    let x = email
    // ruleid: log.swift.print
    print(x)
}

// scenario: concat
func concat(email: String) {
    let msg = "signup \(email)"
    // ruleid: log.swift.print
    print(msg)
}

// scenario: field
func field(u: User) {
    // ruleid: log.swift.print
    print(u.email)
}

// scenario: getter
func getter(u: User) {
    // ruleid: log.swift.print
    print(u.contactEmail())
}

// scenario: key
func key(value: String) {
    let payload = ["email": value]
    // ruleid: log.swift.print
    print(payload)
}

func logIt(_ v: String) {
    // ruleid: log.swift.print
    print(v)
}

// scenario: call-arg
func callArg(email: String) {
    logIt(email)
}

func normalize(_ s: String) -> String {
    return s.trimmingCharacters(in: .whitespaces).lowercased()
}

// scenario: call-return
func callReturn(email: String) {
    // ruleid: log.swift.print
    print(normalize(email))
}

// scenario: closure
func closure(email: String, items: [String]) {
    items.forEach { it in
        // ruleid: log.swift.print
        print(it, email)
    }
}

// scenario: field-store
func fieldStore(phoneNumber: String) {
    let u = User(id: 1, email: "")
    u.contact = phoneNumber
    // ruleid: log.swift.print
    print(u.contact)
}

// scenario: collection
func collection(email: String) {
    var xs: [String] = []
    xs.append(email)
    // ruleid: log.swift.print
    print(xs)
}

// scenario: object
func whole(p: Profile) {
    // ruleid: log.swift.print
    print(p)
}

func maskEmail(_ e: String) -> String {
    return String(e.prefix(1)) + "***"
}

// scenario: masked
func masked(email: String) {
    // ok: log.swift.print
    print(maskEmail(email))
}

// scenario: not-pii
func notPii(u: User, orderId: String, count: Int) {
    // ok: log.swift.print
    print(u.id, orderId, count)
}

// scenario: negative-context
func negativeContext(phoneCount: Int, emailTemplate: String) {
    // ok: log.swift.print
    print(phoneCount, emailTemplate)
}

// scenario: overwritten
func overwritten(email: String) {
    var x = email
    x = "anonymous"
    // ok: log.swift.print
    print(x)
}

// scenario: remasked
func remasked(email: String) {
    var userEmail = email
    userEmail = maskEmail(userEmail)
    // ok: log.swift.print
    print(userEmail)
}

// scenario: branch-merge
func branchMerge(email: String, verbose: Bool) {
    var x = "anonymous"
    if verbose {
        x = email
    }
    // ruleid: log.swift.print
    print(x)
}

// scenario: loop-carried
func loopCarried(email: String, items: [String]) {
    var x = "anonymous"
    for _ in items {
        // ruleid: log.swift.print
        print(x)
        x = email
    }
}

// scenario: mutated-later
func mutatedLater(email: String) {
    var xs: [String] = []
    // ok: log.swift.print
    print(xs)
    xs.append(email)
}

// scenario: early-return
func earlyReturn(email: String, invalid: Bool) {
    var x = "anonymous"
    if invalid {
        x = email
        // ruleid: log.swift.print
        print(x)
        return
    }
    // ok: log.swift.print
    print(x)
}

// scenario: break-exit
func breakExit(email: String, items: [String]) {
    var x = "anonymous"
    for item in items {
        if item.isEmpty {
            x = email
            break
        }
    }
    // ruleid: log.swift.print
    print(x)
}

// scenario: continue-skip
func continueSkip(email: String, items: [String]) {
    for item in items {
        var x = "anonymous"
        if item.isEmpty {
            x = email
            continue
        }
        // ok: log.swift.print
        print(x)
    }
}

// scenario: snapshot
func snapshot(email: String) {
    var items: [String] = []
    let msg = "items=\(items)"
    items.append(email)
    // ok: log.swift.print
    print(msg)
}

enum LogConfig {
    static let verbose = false
}

// scenario: constant-condition
func constantCondition(email: String) {
    if LogConfig.verbose {
        // ok: log.swift.print
        print(email)
    }
}

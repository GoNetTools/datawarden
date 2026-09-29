// Level 3: collections, closures, errors, consent checks, sanitizers and
// objects that keep what their initializer was given.
import FirebaseAnalytics
import Foundation

struct Member {
    let name: String
    let email: String
}

// S15: a collection built in a loop.
func s15Collection(members: [Member]) {
    var emails: [String] = []
    for m in members {
        emails.append(m.email)
    }
    // ruleid: log.swift.print
    print("newsletter to \(emails.joined(separator: ","))")
}

// S16: a closure captures the value.
func s16Closure(phoneNumber: String, codes: [String]) {
    let send: (String) -> Void = { code in
        // ruleid: log.swift.print
        print("sms \(phoneNumber) \(code)")
    }
    codes.forEach(send)
}

struct AccountNotFound: Error {
    let message: String
}

func lookupAccount(email: String) throws {
    throw AccountNotFound(message: "no account for \(email)")
}

// S17: the value travels in an error.
func s17Error(email: String) {
    do {
        try lookupAccount(email: email)
    } catch {
        // ruleid: log.swift.print
        print("lookup failed: \(error)")
    }
}

protocol Consents {
    func hasAnalyticsConsent() -> Bool
}

// S18: analytics sent only after a consent check. Reported with the check;
// accepted when policy.consent_guarded lists third_party.
func s18ConsentGuarded(email: String, consents: Consents) {
    guard consents.hasAnalyticsConsent() else { return }
    // ruleid: sdk.swift.firebase.analytics
    Analytics.logEvent("sign_up", parameters: ["email": email])
}

func isMasked(_ value: String) -> Bool { value.contains("***") }

// S19: logged only when a check says it is already masked.
func s19Sanitizer(email: String) {
    if isMasked(email) {
        // ok: log.swift.print
        print("contact \(email)")
    }
}

final class Session {
    private let userId: String
    private let accessToken: String

    init(userId: String, token: String) {
        self.userId = userId
        self.accessToken = token
    }

    // S20: the initializer stores the value, another method logs it.
    func debug() {
        // ruleid: log.swift.print
        print("session user=\(userId) token=\(accessToken)")
    }
}

func s20ConstructorField(userId: String, token: String) {
    Session(userId: userId, token: token).debug()
}

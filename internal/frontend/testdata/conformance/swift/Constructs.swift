// Language constructs the Swift frontend must lower. Unlike the shared
// scenarios in Conformance.swift, these are specific to Swift.
import Foundation
import os

struct Account {
    var firstName: String
    var lastName: String
    var phone: String?

    var fullName: String { firstName + " " + lastName }
}

final class SignupController {
    private let logger = Logger(subsystem: "shop", category: "signup")
    var email = ""

    func submit() {
        // ruleid: log.swift.print
        print("submitting", email)
    }

    func remember(_ address: String) {
        email = address
        submit()
    }

    static func announce(phone: String) {
        // ruleid: log.swift.print
        print("sms to", phone)
    }

    func unifiedLogging(email: String) {
        // ok: log.swift.os_log
        logger.info("signup \(email)")
        // ruleid: log.swift.os_log
        logger.info("signup \(email, privacy: .public)")
        // ok: log.swift.os_log
        os_log("signup %@", email)
        // ruleid: log.swift.os_log
        os_log("signup %{public}@", email)
    }
}

extension Account {
    func describe() -> String {
        return "account \(firstName)"
    }
}

func optionalBinding(account: Account) {
    if let phone = account.phone {
        // ruleid: log.swift.print
        print(phone)
    }
    guard let p = account.phone else { return }
    // ruleid: log.swift.print
    print(p)
}

func optionalChaining(account: Account?) {
    // ruleid: log.swift.print
    print(account?.phone ?? "none")
}

func switchStatement(email: String, kind: Int) {
    switch kind {
    case 1:
        // ruleid: log.swift.print
        print(email)
    default:
        // ok: log.swift.print
        print("none")
    }
}

func doCatch(email: String) throws {
    do {
        try validate(email)
    } catch {
        // ruleid: log.swift.print
        print("invalid", email, error)
    }
}

func validate(_ s: String) throws {}

func trailingClosure(emails: [String]) {
    emails.forEach {
        // ruleid: log.swift.print
        print($0)
    }
    let upper = emails.map { $0.uppercased() }
    // ruleid: log.swift.print
    print(upper)
}

func computedProperty(account: Account) {
    // ruleid: log.swift.print
    print(account.fullName)
}

func extensionMethod(account: Account) {
    // ruleid: log.swift.print
    print(account.describe())
}

func fetchProfile(email: String) async -> String {
    return email
}

func asyncAwait(email: String) async {
    let profile = await fetchProfile(email: email)
    // ruleid: log.swift.print
    print(profile)
}

func subscripts(payload: [String: String]) {
    // ruleid: log.swift.print
    print(payload["phone_number"] ?? "")
    // ok: log.swift.print
    print(payload["order_id"] ?? "")
}

func tuples(account: Account) {
    let (first, _) = (account.firstName, account.lastName)
    // ruleid: log.swift.print
    print(first)
}

func ternary(account: Account, useName: Bool) {
    let label = useName ? account.firstName : "guest"
    // ruleid: log.swift.print
    print(label)
}

func nestedFunction(email: String) {
    func shout(_ s: String) -> String {
        return s.uppercased()
    }
    // ruleid: log.swift.print
    print(shout(email))
}

func compoundAssignment(email: String) {
    var msg = "to: "
    msg += email
    // ruleid: log.swift.print
    print(msg)
}

func subscriptStore(phone: String) {
    var payload: [String: String] = [:]
    payload["phone"] = phone
    // ruleid: log.swift.print
    print(payload)
}

final class Card {
    var holder = ""
}

func fieldStore(email: String) {
    let card = Card()
    card.holder = email
    // ruleid: log.swift.print
    print(card.holder)
}

func record(_ value: String) {
    // ruleid: log.swift.print
    print("recorded", value)
}

func record(_ value: Int) {
    // ok: log.swift.print
    print("recorded", value)
}

func overloads(email: String) {
    record(email)
}

func dictionaryLoop(contacts: [String: String]) {
    for (name, phone) in contacts {
        // ruleid: log.swift.print
        print(name, phone)
    }
}

func whileLoop(emails: [String]) {
    var i = 0
    while i < emails.count {
        // ruleid: log.swift.print
        print(emails[i])
        i += 1
    }
}

func switchOverwrites(email: String, kind: Int) {
    var x = email
    switch kind {
    case 1: x = "one"
    default: x = "other"
    }
    // ok: log.swift.print
    print(x)
}

func guardKeepsBinding(email: String?) {
    var x = "anonymous"
    guard let userEmail = email else {
        x = "missing"
        return
    }
    // ruleid: log.swift.print
    print(userEmail)
    // ok: log.swift.print
    print(x)
}

func catchSeesEarlierValue(email: String) {
    var x = email
    do {
        x = "cleared"
        try JSONSerialization.jsonObject(with: Data(x.utf8))
    } catch {
        // ruleid: log.swift.print
        print(x)
    }
}

func labeledBreak(email: String, rows: [[String]]) {
    var x = "anonymous"
    outer: for row in rows {
        for cell in row {
            if cell.isEmpty {
                x = email
                break outer
            }
        }
        x = "reset"
    }
    // ruleid: log.swift.print
    print(x)
}

final class Account {
    private let mail: String
    init(_ mail: String) { self.mail = mail }
    var contact: String { mail }
}

func computedProperty(email: String) {
    // ruleid: log.swift.print
    print(Account(email).contact)
}

func caseBinding(email: String?) {
    switch email {
    case .some(let address):
        // ruleid: log.swift.print
        print(address)
    default:
        break
    }
}

// Swift 5.9–6 syntax the grammar predates (typed throws, ownership
// modifiers, suppressed conformances, await in conditions, macros) is
// blanked before parsing; the code around it is analysed as usual.
enum LookupError: Error { case missing }

struct Token: ~Copyable {
    let value: String
}

func lookup(_ email: consuming String) async throws(LookupError) -> sending String {
    email
}

func modernSyntax(email: String) async {
    if let found = try? await lookup(email),
        !found.isEmpty
    {
        // ruleid: log.swift.print
        print(found)
    }
    let other = "anonymous"
    // ok: log.swift.print
    print(other)
}

func emptyPattern(result: Result<Void, LookupError>, email: String) {
    switch result {
    case .success(): print("done")
    case .failure(_):
        // ruleid: log.swift.print
        print(email)
    }
}

#Preview {
    Text("preview")
}

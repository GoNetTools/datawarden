// Level 4: dynamic dispatch, callbacks kept in properties, deep objects,
// multi-layer pipelines, device storage and ordering.
import Foundation
import UIKit

protocol Notifier {
    func notify(to: String, body: String)
}

final class SmsNotifier: Notifier {
    func notify(to: String, body: String) {
        // ruleid: log.swift.print
        print("sms to=\(to) body=\(body)")
    }
}

final class PushNotifier: Notifier {
    private(set) var sent = 0
    func notify(to: String, body: String) {
        sent += 1
    }
}

// S21: the value reaches the sink through a protocol call.
func s21Dispatch(notifier: Notifier, phoneNumber: String) {
    notifier.notify(to: phoneNumber, body: "your code is ready")
}

final class EventBus {
    private var onSignup: ((String) -> Void)?

    func subscribe(_ handler: @escaping (String) -> Void) {
        onSignup = handler
    }

    func publish(email: String) {
        onSignup?(email)
    }
}

// S22: a callback kept in a property runs later with the value.
func s22StoredCallback(bus: EventBus, emailAddress: String) {
    bus.subscribe { e in
        // ruleid: log.swift.print
        print("welcome mail queued for \(e)")
    }
    bus.publish(email: emailAddress)
}

struct Contact { let homeAddress: String }
struct Customer { let contact: Contact }
struct Order {
    let id: String
    let customer: Customer
}

// S23: a value three properties deep.
func s23DeepField(order: Order) async throws {
    let request = URLRequest(url: URL(string: "https://shipping.partner.example/labels")!)
    let label = try JSONEncoder().encode(["to": order.customer.contact.homeAddress])
    // ruleid: net.swift.urlsession
    let (_, _) = try await URLSession.shared.upload(for: request, from: label)
    let status = try JSONEncoder().encode(["order": order.id])
    // ok: net.swift.urlsession
    let (_, _) = try await URLSession.shared.upload(for: request, from: status)
}

final class ProfileRepo {
    func save(userId: String, dateOfBirth: String) {
        // ruleid: storage.swift.user_defaults
        UserDefaults.standard.set(dateOfBirth, forKey: "dob.\(userId)")
    }
}

final class ProfileService {
    private let repo: ProfileRepo

    init(repo: ProfileRepo) {
        self.repo = repo
    }

    func update(userId: String, dob: String) async throws {
        repo.save(userId: userId, dateOfBirth: dob)
        let request = URLRequest(url: URL(string: "https://age-check.partner.example/v1")!)
        let body = try JSONEncoder().encode(["dob": dob])
        // ruleid: net.swift.urlsession
        let (_, _) = try await URLSession.shared.upload(for: request, from: body)
    }
}

// S24: form input → service → repository and partner.
func s24Pipeline(svc: ProfileService, userId: String, dateOfBirth: String) async throws {
    try await svc.update(userId: userId, dob: dateOfBirth)
}

// S25: a session token persisted on the device, and copied to the
// pasteboard where other apps can read it.
func s25DeviceStorage(sessionToken: String) {
    // ruleid: storage.swift.user_defaults
    UserDefaults.standard.set(sessionToken, forKey: "session")
    // ruleid: ipc.swift.pasteboard
    UIPasteboard.general.string = sessionToken
}

// S26: an object logged before the value is added to it, then after.
func s26Ordering(email: String) {
    var payload = ["source": "web"]
    // ok: log.swift.print
    print("payload \(payload)")
    payload["email"] = email
    // ruleid: log.swift.print
    print("payload \(payload)")
}

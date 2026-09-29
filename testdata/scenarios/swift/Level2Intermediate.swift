// Level 2: a value is formatted, stored in an object or a dictionary, or
// passed to a helper before it reaches a sink.
import Foundation
import Sentry

// S08: health data formatted into a message.
func s08Formatted(patientId: Int, diagnosis: String) {
    let msg = String(format: "patient %d diagnosis %@", patientId, diagnosis)
    // ruleid: log.swift.print
    print(msg)
}

struct PaymentCard {
    let holder: String
    let cardNumber: String
    let expiry: String
}

// S09: a field of an object written to a file.
func s09ObjectField(card: PaymentCard, dir: URL) throws {
    // ruleid: storage.swift.write_file
    try Data(card.cardNumber.utf8).write(to: dir.appendingPathComponent("last-card.txt"))
    // ok: storage.swift.write_file
    try Data(card.expiry.utf8).write(to: dir.appendingPathComponent("last-expiry.txt"))
}

// S10: a dictionary key says what its value is.
func s10DictionaryKey(value: String) async throws {
    var request = URLRequest(url: URL(string: "https://kyc.partner.example/verify")!)
    request.httpMethod = "POST"
    let body = try JSONEncoder().encode(["ssn": value])
    // ruleid: net.swift.urlsession
    let (_, _) = try await URLSession.shared.upload(for: request, from: body)
}

// auditLog is a helper several scenarios call.
func auditLog(_ event: String, _ detail: String) {
    // ruleid: log.swift.print
    print("audit", event, detail)
}

// S11: the value is logged by a helper.
func s11Helper(email: String) {
    auditLog("login", email)
}

final class Patient {
    let id: Int
    private let mrn: String

    init(id: Int, mrn: String) {
        self.id = id
        self.mrn = mrn
    }

    var medicalRecordNumber: String { mrn }
}

// S12: a computed property returns the value.
func s12Getter(patient: Patient) {
    // ruleid: sdk.swift.sentry
    SentrySDK.addBreadcrumb(Breadcrumb(level: .info, category: "record \(patient.medicalRecordNumber)"))
}

// S13: the value is replaced on one path before it is logged.
func s13Overwritten(email: String, anonymous: Bool) {
    var shown = email
    if anonymous {
        shown = "anonymous"
        // ok: log.swift.print
        print("comment by \(shown)")
        return
    }
    // ruleid: log.swift.print
    print("comment by \(shown)")
}

// S14: an API key sent to the service it authenticates to.
func s14CredentialToItsService(apiKey: String) async throws {
    var request = URLRequest(url: URL(string: "https://api.payments.example/v1/balance")!)
    request.setValue("Bearer \(apiKey)", forHTTPHeaderField: "Authorization")
    // ok: net.swift.urlsession
    let (_, _) = try await URLSession.shared.data(for: request)
}

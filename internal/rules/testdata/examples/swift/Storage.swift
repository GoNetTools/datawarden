// Examples for the Swift storage, network and IPC rules.
import Foundation
import UIKit

func userDefaults(email: String, theme: String) {
    // ruleid: storage.swift.user_defaults
    UserDefaults.standard.set(email, forKey: "lastEmail")
    // ok: storage.swift.user_defaults
    UserDefaults.standard.set(theme, forKey: "theme")
}

func files(email: String) {
    // ruleid: storage.swift.file
    FileManager.default.createFile(atPath: "/tmp/export.txt", contents: Data(email.utf8))
}

func plist(email: String, path: String) {
    let content = NSDictionary(dictionary: ["email": email])
    // ruleid: storage.swift.write_file
    content.write(toFile: path, atomically: true)
}

func network(email: String) async throws {
    var request = URLRequest(url: URL(string: "https://crm.partner.example/leads")!)
    request.httpMethod = "POST"
    let body = try JSONEncoder().encode(["email": email])
    // ruleid: net.swift.urlsession
    let (_, _) = try await URLSession.shared.upload(for: request, from: body)
}

func pasteboard(phone: String) {
    // ruleid: ipc.swift.pasteboard
    UIPasteboard.general.string = phone
}

// Checkout screen of the vulnshop iOS app. Vulnerable by design: "LEAK"
// comments mark personal data reaching a place it should not, "SAFE"
// comments mark look-alikes a scanner must not report.
import FirebaseAnalytics
import FirebaseCrashlytics
import Foundation
import os
import UIKit

struct Shopper: Codable {
    let id: String
    let email: String
    let phoneNumber: String
    let nickname: String
}

final class CheckoutViewModel {
    private let logger = Logger(subsystem: "shop.vulnshop", category: "checkout")

    func placeOrder(shopper: Shopper, cardNumber: String) {
        // LEAK: email as the Crashlytics user id.
        Crashlytics.crashlytics().setUserID(shopper.email)
        // LEAK: phone number in an analytics event.
        Analytics.logEvent("order_placed", parameters: ["phone": shopper.phoneNumber])
        // LEAK: card number marked public in the unified log.
        logger.error("payment failed for \(cardNumber, privacy: .public)")
        // SAFE: private by default, redacted in the unified log.
        logger.info("order placed by \(shopper.email)")
        // SAFE: the id and nickname only.
        print("order for", shopper.id, shopper.nickname)
        // LEAK: email kept in UserDefaults, an unencrypted plist.
        UserDefaults.standard.set(shopper.email, forKey: "lastEmail")
    }

    func copyCard(cardNumber: String) {
        // LEAK: card number on the general pasteboard, readable by other apps.
        UIPasteboard.general.string = cardNumber
    }

    func sendReceipt(shopper: Shopper) async throws {
        var request = URLRequest(url: URL(string: "https://mail.partner.example/v1/send")!)
        request.httpMethod = "POST"
        // LEAK: email sent to a mailing vendor.
        request.httpBody = try JSONEncoder().encode(["to": shopper.email])
        _ = try await URLSession.shared.data(for: request)
    }
}

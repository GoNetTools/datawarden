// Examples for the Swift logging rules. Unified logging (Logger, os_log)
// redacts values unless they are marked public.
import Foundation
import os

final class OtpService {
    private let logger = Logger(subsystem: "shop", category: "otp")

    func send(phone: String, orderId: String) {
        // ruleid: log.swift.print
        print("otp to", phone)
        // ruleid: log.swift.print
        NSLog("otp to %@", phone)
        // ruleid: log.swift.print
        debugPrint(phone)
        // ok: log.swift.print
        print("order", orderId)
        // ruleid: log.swift.os_log
        logger.error("otp failed for \(phone, privacy: .public)")
        // ok: log.swift.os_log
        logger.error("otp failed for \(phone)")
        // ruleid: log.swift.os_log
        os_log("otp failed for %{public}@", phone)
    }
}

// Examples for the Swift transform rules. A hash is not a safe transform
// by default (phone numbers can be enumerated), so logging it is still a
// violation; encryption is safe.
import CryptoKit
import Foundation

func sha256(phoneNumber: String) {
    // ruleid: xform.swift.sha256
    let digest = SHA256.hash(data: Data(phoneNumber.utf8))
    // ruleid: log.swift.print
    print("lookup", digest)
}

func sha512(email: String) {
    // ruleid: xform.swift.sha512
    let digest = SHA512.hash(data: Data(email.utf8))
    // ruleid: log.swift.print
    print("key", digest)
}

func weakHash(email: String) {
    // ruleid: xform.swift.weak_hash
    let digest = Insecure.MD5.hash(data: Data(email.utf8))
    // ruleid: log.swift.print
    print("gravatar", digest)
}

func encrypt(email: String, key: SymmetricKey) throws {
    // ruleid: xform.swift.encrypt
    let sealed = try AES.GCM.seal(Data(email.utf8), using: key)
    // ok: log.swift.print
    print("sealed", sealed)
}

func encode(email: String) {
    // ruleid: xform.swift.base64
    let blob = Data(email.utf8).base64EncodedString()
    // ruleid: log.swift.print
    print("blob", blob)
}

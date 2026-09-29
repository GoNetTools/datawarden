// Level 1: a value reaches a sink in the function it arrives in.
package scenarios

import android.util.Log
import java.security.MessageDigest

private const val TAG = "Scenarios"

// S01: a parameter logged as it arrives.
fun s01DirectParam(email: String) {
    // ruleid: log.android.logcat
    Log.i(TAG, "signup $email")
}

// S02: a local variable named for what it holds.
fun s02LocalVariable(raw: String) {
    val phoneNumber = raw.trim()
    // ruleid: log.android.logcat
    Log.d(TAG, "otp sent to $phoneNumber")
}

// S03: values that are not personal data, and names that only look like it.
fun s03NotPersonal(orderId: String, itemCount: Int, emailEnabled: Boolean, phoneFormatter: String) {
    // ok: log.android.logcat
    Log.i(TAG, "order $orderId items $itemCount")
    // ok: log.android.logcat
    Log.i(TAG, "email notifications $emailEnabled")
    // ok: log.android.logcat
    Log.i(TAG, "format $phoneFormatter")
}

// S04: a credential logged.
fun s04Credential(username: String, password: String) {
    // ruleid: log.android.logcat
    Log.w(TAG, "login $username/$password")
}

fun maskEmail(email: String): String {
    val at = email.indexOf('@')
    return if (at > 0) email.take(1) + "***" + email.substring(at) else "***"
}

// S05: masked before it is logged.
fun s05Masked(email: String) {
    // ok: log.android.logcat
    Log.i(TAG, "reset link sent to ${maskEmail(email)}")
}

// S06: a hash of personal data still identifies the person.
fun s06HashedPersonal(email: String) {
    val digest = MessageDigest.getInstance("SHA-256").digest(email.toByteArray())
    // ruleid: log.android.logcat
    Log.i(TAG, "lookup key ${digest.contentToString()}")
}

// S07: a hashed password is safe to log.
fun s07HashedCredential(password: String) {
    val digest = MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
    // ok: log.android.logcat
    Log.i(TAG, "password fingerprint ${digest.contentToString()}")
}

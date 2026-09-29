// Level 3: collections, lambdas, exceptions, consent checks, sanitizers
// and objects that keep what their constructor was given.
package scenarios

import android.util.Log
import com.segment.analytics.Analytics
import com.segment.analytics.Properties

private const val L3 = "Level3"

data class Member(val name: String, val email: String)

// S15: a collection built in a loop.
fun s15Collection(members: List<Member>) {
    val emails = mutableListOf<String>()
    for (m in members) {
        emails.add(m.email)
    }
    // ruleid: log.android.logcat
    Log.i(L3, "newsletter to ${emails.joinToString(",")}")
}

// S16: a lambda captures the value.
fun s16Lambda(phoneNumber: String, codes: List<String>) {
    val send: (String) -> Unit = { code ->
        // ruleid: log.android.logcat
        Log.i(L3, "sms $phoneNumber $code")
    }
    codes.forEach(send)
}

class AccountNotFoundException(message: String) : RuntimeException(message)

fun lookupAccount(email: String): Nothing = throw AccountNotFoundException("no account for $email")

// S17: the value travels in an exception.
fun s17Exception(email: String) {
    try {
        lookupAccount(email)
    } catch (e: AccountNotFoundException) {
        // ruleid: log.android.logcat
        Log.w(L3, "lookup failed: ${e.message}")
    }
}

interface Consents {
    fun hasAnalyticsConsent(): Boolean
}

// S18: analytics sent only after a consent check. Reported with the check;
// accepted when policy.consent_guarded lists third_party.
fun s18ConsentGuarded(analytics: Analytics, email: String, consents: Consents) {
    if (!consents.hasAnalyticsConsent()) return
    // ruleid: sdk.segment
    analytics.track("signup", Properties().putValue("email", email))
}

fun isMasked(value: String): Boolean = value.contains("***")

// S19: logged only when a check says it is already masked.
fun s19Sanitizer(email: String) {
    if (isMasked(email)) {
        // ok: log.android.logcat
        Log.i(L3, "contact $email")
    }
}

class Session(private val userId: String, token: String) {
    private val accessToken = token

    // S20: the constructor stores the value, another method logs it.
    fun debug() {
        // ruleid: log.android.logcat
        Log.d(L3, "session user=$userId token=$accessToken")
    }
}

fun s20ConstructorField(userId: String, token: String) {
    Session(userId, token).debug()
}

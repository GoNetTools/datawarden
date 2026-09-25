// Examples for the crash-reporting SDK sinks.
package examples.crash

import com.bugsnag.android.Bugsnag
import com.google.firebase.crashlytics.FirebaseCrashlytics
import io.sentry.Sentry
import io.sentry.protocol.User

class CrashReporting {
    fun sentryUser(userEmail: String) {
        // ruleid: sdk.sentry.set_user
        Sentry.setUser(User().apply { email = userEmail })
    }

    fun sentryMessage(email: String) {
        // ruleid: sdk.sentry.capture
        Sentry.captureMessage("password reset for $email")
    }

    fun sentryExtra(phoneNumber: String) {
        // ruleid: sdk.sentry.set_extra
        Sentry.setExtra("phone", phoneNumber)
        // ok: sdk.sentry.set_extra
        Sentry.setExtra("plan", "pro")
    }

    fun crashlytics(email: String, cccd: String) {
        // ruleid: sdk.firebase.crashlytics
        FirebaseCrashlytics.getInstance().setUserId(email)
        // ruleid: sdk.firebase.crashlytics.custom_key
        FirebaseCrashlytics.getInstance().setCustomKey("cccd", cccd)
    }

    fun bugsnag(email: String, fullName: String) {
        // ruleid: sdk.bugsnag
        Bugsnag.setUser("42", email, fullName)
    }
}

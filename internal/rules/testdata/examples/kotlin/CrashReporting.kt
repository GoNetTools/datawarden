// Examples for the crash-reporting SDK sinks.
package examples.crash

import com.bugsnag.android.Bugsnag
import com.datadog.android.Datadog
import com.datadog.android.rum.GlobalRumMonitor
import com.newrelic.agent.android.NewRelic
import com.rollbar.android.Rollbar
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

    fun crashlytics(email: String, nationalId: String) {
        // ruleid: sdk.firebase.crashlytics
        FirebaseCrashlytics.getInstance().setUserId(email)
        // ruleid: sdk.firebase.crashlytics.custom_key
        FirebaseCrashlytics.getInstance().setCustomKey("national_id", nationalId)
    }

    fun bugsnag(email: String, fullName: String) {
        // ruleid: sdk.bugsnag
        Bugsnag.setUser("42", email, fullName)
    }

    fun rollbar(email: String, orderId: Long) {
        // ruleid: sdk.rollbar
        Rollbar.instance().info("password reset for $email")
        // ok: sdk.rollbar
        Rollbar.instance().error("order $orderId failed")
    }

    fun datadog(userId: String, email: String, cartSize: Int) {
        // ruleid: sdk.datadog
        Datadog.setUserInfo(userId, null, email)
        // ok: sdk.datadog
        GlobalRumMonitor.get().addAttribute("cart_size", cartSize)
    }

    fun newRelic(phoneNumber: String, screen: String) {
        // ruleid: sdk.newrelic
        NewRelic.setAttribute("phone", phoneNumber)
        // ok: sdk.newrelic
        NewRelic.recordBreadcrumb(screen)
    }
}

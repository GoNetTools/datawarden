// Examples for the Swift SDK rules.
import Amplitude
import Bugsnag
import BrazeKit
import DatadogCore
import DatadogRUM
import FirebaseAnalytics
import FirebaseCrashlytics
import Mixpanel
import Segment
import Sentry

func sentry(email: String, userId: String) {
    let user = User(userId: userId)
    user.email = email
    // ruleid: sdk.swift.sentry
    SentrySDK.setUser(user)
    SentrySDK.configureScope { scope in
        // ruleid: sdk.swift.sentry
        scope.setExtra(value: email, key: "email")
    }
    // ok: sdk.swift.sentry
    SentrySDK.setUser(User(userId: userId))
}

func firebase(email: String, phone: String) {
    // ruleid: sdk.swift.firebase.analytics
    Analytics.setUserID(email)
    // ruleid: sdk.swift.firebase.analytics
    Analytics.logEvent("signup", parameters: ["phone": phone])
    // ruleid: sdk.swift.firebase.crashlytics
    Crashlytics.crashlytics().setUserID(email)
    // ok: sdk.swift.firebase.crashlytics
    Crashlytics.crashlytics().log("signup finished")
}

func mixpanel(email: String) {
    // ruleid: sdk.swift.mixpanel
    Mixpanel.mainInstance().identify(distinctId: email)
    // ruleid: sdk.swift.mixpanel
    Mixpanel.mainInstance().people.set(properties: ["$email": email])
}

func amplitude(email: String) {
    // ruleid: sdk.swift.amplitude
    Amplitude.instance().setUserId(email)
}

func bugsnag(email: String, userId: String) {
    // ruleid: sdk.swift.bugsnag
    Bugsnag.setUser(userId, withEmail: email, andName: nil)
    // ok: sdk.swift.bugsnag
    Bugsnag.leaveBreadcrumb(withMessage: "checkout started")
}

func datadog(userId: String, email: String, cartSize: Int) {
    // ruleid: sdk.swift.datadog
    Datadog.setUserInfo(id: userId, name: nil, email: email)
    // ok: sdk.swift.datadog
    RUMMonitor.shared().addAttribute(forKey: "cart_size", value: cartSize)
}

func segment(email: String) {
    // ruleid: sdk.swift.segment
    Analytics.shared().identify("user-1", traits: ["email": email])
    // ok: sdk.swift.segment
    Analytics.shared().track("Checkout Started")
}

func braze(braze: Braze, email: String, phoneNumber: String) {
    // ruleid: sdk.swift.braze
    braze.user.set(email: email)
    // ruleid: sdk.swift.braze
    braze.logCustomEvent(name: "otp_sent", properties: ["phone": phoneNumber])
    // ok: sdk.swift.braze
    braze.logCustomEvent(name: "app_opened")
}

// Examples for the Swift SDK rules.
import Amplitude
import FirebaseAnalytics
import FirebaseCrashlytics
import Mixpanel
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

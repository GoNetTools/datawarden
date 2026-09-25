// Examples for the analytics and engagement SDK sinks.
package examples.analytics

import android.content.Context
import androidx.core.os.bundleOf
import com.amplitude.android.Amplitude
import com.appsflyer.AppsFlyerLib
import com.braze.Braze
import com.clevertap.android.sdk.CleverTapAPI
import com.facebook.appevents.AppEventsLogger
import com.google.firebase.analytics.FirebaseAnalytics
import com.mixpanel.android.mpmetrics.MixpanelAPI
import com.onesignal.OneSignal
import com.segment.analytics.Analytics
import com.segment.analytics.Properties
import io.intercom.android.sdk.Intercom
import io.intercom.android.sdk.UserAttributes
import org.json.JSONObject

class Tracking(
    private val context: Context,
    private val firebaseAnalytics: FirebaseAnalytics,
    private val mixpanel: MixpanelAPI,
    private val analytics: Analytics,
    private val amplitude: Amplitude,
    private val cleverTap: CleverTapAPI,
) {
    fun firebase(phoneNumber: String, email: String, plan: String) {
        // ruleid: sdk.firebase.analytics
        firebaseAnalytics.logEvent("sign_up", bundleOf("phone" to phoneNumber))
        // ok: sdk.firebase.analytics
        firebaseAnalytics.logEvent("upgrade", bundleOf("plan" to plan))
        // ruleid: sdk.firebase.analytics.user_id
        firebaseAnalytics.setUserId(email)
    }

    fun mixpanel(email: String) {
        val props = JSONObject().put("email", email)
        // ruleid: sdk.mixpanel
        mixpanel.track("signup", props)
    }

    fun segment(email: String) {
        // ruleid: sdk.segment
        analytics.track("signup", Properties().putValue("email", email))
    }

    fun amplitude(dateOfBirth: String) {
        // ruleid: sdk.amplitude
        amplitude.track("profile_completed", mapOf("dob" to dateOfBirth))
    }

    fun appsFlyer(email: String) {
        // ruleid: sdk.appsflyer
        AppsFlyerLib.getInstance().setCustomerUserId(email)
    }

    fun facebook(email: String) {
        // ruleid: sdk.facebook.app_events
        AppEventsLogger.setUserID(email)
    }

    fun oneSignal(phoneNumber: String) {
        // ruleid: sdk.onesignal
        OneSignal.User.addSms(phoneNumber)
    }

    fun cleverTap(email: String) {
        val profile = hashMapOf<String, Any>("Email" to email)
        // ruleid: sdk.clevertap
        cleverTap.onUserLogin(profile)
    }

    fun braze(email: String) {
        // ruleid: sdk.braze
        Braze.getInstance(context).changeUser(email)
    }

    fun intercom(email: String) {
        val attributes = UserAttributes.Builder().withEmail(email).build()
        // ruleid: sdk.intercom
        Intercom.client().updateUser(attributes)
    }
}

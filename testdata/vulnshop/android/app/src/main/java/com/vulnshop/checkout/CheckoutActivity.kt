package com.vulnshop.checkout

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.location.LocationManager
import android.telephony.TelephonyManager
import android.util.Log
import com.amplitude.android.Amplitude
import com.google.firebase.analytics.FirebaseAnalytics
import timber.log.Timber

// Vulnerable by design: "LEAK" comments mark personal data reaching a place
// it should not, "SAFE" comments mark look-alikes a scanner must not report.
class CheckoutActivity(
    private val context: Context,
    private val firebaseAnalytics: FirebaseAnalytics,
    private val amplitude: Amplitude,
) {
    fun onSignedIn(email: String) {
        // LEAK: email as the analytics user id.
        firebaseAnalytics.setUserId(email)
    }

    fun onOtpRequested(phoneNumber: String) {
        // LEAK: phone number to logcat through Timber.
        Timber.d("OTP sent to %s", phoneNumber)
    }

    fun copyCard(cardNumber: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        // LEAK: card number on the clipboard, readable by other apps and keyboards.
        clipboard.setPrimaryClip(ClipData.newPlainText("card", cardNumber))
    }

    fun prefillPhone(telephony: TelephonyManager) {
        val line = telephony.line1Number
        // LEAK: the device's own phone number to logcat.
        Log.i(TAG, "prefill $line")
    }

    fun trackDelivery(locationManager: LocationManager) {
        val loc = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        // LEAK: precise location to Amplitude.
        amplitude.track("delivery_check", mapOf("lat" to loc?.latitude, "lng" to loc?.longitude))
    }

    fun onCartChanged(items: List<String>, orderId: String) {
        // SAFE: cart size and order id.
        Log.d(TAG, "cart size ${items.size} order $orderId")
    }

    fun onPhoneVerified(phoneNumber: String) {
        // SAFE: masked.
        Log.d(TAG, "verified ${phoneNumber.maskPhone()}")
    }

    companion object {
        private const val TAG = "Checkout"
    }
}

fun String.maskPhone(): String = take(3) + "*******"

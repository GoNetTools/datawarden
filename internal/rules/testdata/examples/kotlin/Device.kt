// Examples for on-device storage, IPC and WebView sinks, and the Android
// source APIs as Kotlin code usually calls them.
package examples.device

import android.accounts.AccountManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.location.LocationManager
import android.provider.ContactsContract
import android.telephony.TelephonyManager
import android.util.Log
import android.webkit.WebView
import com.google.android.gms.ads.identifier.AdvertisingIdClient
import java.io.File

class DeviceData(private val context: Context, private val prefs: SharedPreferences) {
    fun sharedPrefs(phoneNumber: String) {
        // ruleid: storage.android.shared_prefs
        prefs.edit().putString("phone", phoneNumber).apply()
    }

    fun file(email: String) {
        // ruleid: storage.jvm.file
        File(context.filesDir, "export.csv").writeText(email)
    }

    fun clipboard(cardNumber: String) {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        // ruleid: ipc.android.clipboard
        clipboard.setPrimaryClip(ClipData.newPlainText("card", cardNumber))
    }

    fun broadcast(email: String) {
        val intent = Intent("com.shop.PROFILE_UPDATED").putExtra("email", email)
        // ruleid: ipc.android.broadcast
        context.sendBroadcast(intent)
    }

    fun webView(webView: WebView, email: String) {
        // ruleid: net.android.webview
        webView.loadUrl("https://shop.example/track?email=$email")
    }

    fun ownNumber(telephony: TelephonyManager) {
        // todoruleid: src.android.phone_number
        val line = telephony.line1Number
        // todoruleid: log.android.logcat
        Log.i(TAG, "prefill $line")
    }

    fun location(locationManager: LocationManager) {
        // ruleid: src.android.location
        val loc = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        // ruleid: log.android.logcat
        Log.d(TAG, "at $loc")
    }

    fun contacts() {
        // ruleid: src.android.contacts
        val cursor = context.contentResolver.query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI, null, null, null, null)
        // ruleid: log.android.logcat
        Log.d(TAG, "contacts $cursor")
    }

    fun advertisingId() {
        // ruleid: src.android.advertising_id
        val info = AdvertisingIdClient.getAdvertisingIdInfo(context)
        // ruleid: log.android.logcat
        Log.d(TAG, "ad id $info")
    }

    companion object {
        private const val TAG = "Device"
    }
}

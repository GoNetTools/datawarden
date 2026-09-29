// Level 4: dynamic dispatch, listeners kept in fields, deep objects,
// multi-layer pipelines, device storage and ordering.
package scenarios

import android.content.SharedPreferences
import android.database.sqlite.SQLiteDatabase
import android.util.Log
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request

private const val L4 = "Level4"

interface Notifier {
    fun notify(to: String, body: String)
}

class SmsNotifier : Notifier {
    override fun notify(to: String, body: String) {
        // ruleid: log.android.logcat
        Log.i(L4, "sms to=$to body=$body")
    }
}

class PushNotifier : Notifier {
    var sent = 0
    override fun notify(to: String, body: String) {
        sent++
    }
}

// S21: the value reaches the sink through an interface call.
fun s21Dispatch(notifier: Notifier, phoneNumber: String) {
    notifier.notify(phoneNumber, "your code is ready")
}

class EventBus {
    private var onSignup: ((String) -> Unit)? = null

    fun subscribe(handler: (String) -> Unit) {
        onSignup = handler
    }

    fun publish(email: String) {
        onSignup?.invoke(email)
    }
}

// S22: a listener kept in a field runs later with the value.
fun s22StoredCallback(bus: EventBus, emailAddress: String) {
    bus.subscribe { e ->
        // ruleid: log.android.logcat
        Log.i(L4, "welcome mail queued for $e")
    }
    bus.publish(emailAddress)
}

data class Contact(val homeAddress: String)
data class Customer(val contact: Contact)
data class Order(val id: String, val customer: Customer)

// S23: a value three fields deep.
fun s23DeepField(client: OkHttpClient, order: Order) {
    val label = Request.Builder().url("https://shipping.partner.example/labels")
        .post(FormBody.Builder().add("to", order.customer.contact.homeAddress).build()).build()
    // ruleid: net.jvm.okhttp
    client.newCall(label).execute()
    val status = Request.Builder().url("https://shipping.partner.example/status")
        .post(FormBody.Builder().add("order", order.id).build()).build()
    // ok: net.jvm.okhttp
    client.newCall(status).execute()
}

class ProfileRepo(private val db: SQLiteDatabase) {
    fun save(userId: String, dateOfBirth: String) {
        // ruleid: storage.android.sqlite
        db.execSQL("UPDATE profiles SET dob = '$dateOfBirth' WHERE id = '$userId'")
    }
}

class ProfileService(private val repo: ProfileRepo, private val client: OkHttpClient) {
    fun update(userId: String, dob: String) {
        repo.save(userId, dob)
        val request = Request.Builder().url("https://age-check.partner.example/v1")
            .post(FormBody.Builder().add("dob", dob).build()).build()
        // ruleid: net.jvm.okhttp
        client.newCall(request).execute()
    }
}

// S24: form input → service → repository and partner.
fun s24Pipeline(svc: ProfileService, userId: String, dateOfBirth: String) {
    svc.update(userId, dateOfBirth)
}

// S25: a session token persisted on the device.
fun s25DeviceStorage(prefs: SharedPreferences, sessionToken: String) {
    // ruleid: storage.android.shared_prefs
    prefs.edit().putString("session", sessionToken).apply()
}

// S26: an object logged before the value is added to it, then after.
fun s26Ordering(email: String) {
    val payload = mutableMapOf("source" to "web")
    // ok: log.android.logcat
    Log.i(L4, "payload $payload")
    payload["email"] = email
    // ruleid: log.android.logcat
    Log.i(L4, "payload $payload")
}

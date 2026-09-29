// Level 2: a value is formatted, stored in an object or a map, or passed
// to a helper before it reaches a sink.
package scenarios

import android.content.Context
import android.util.Log
import io.sentry.Sentry
import java.io.File
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

private const val L2 = "Level2"

// S08: health data formatted into a message.
fun s08Formatted(patientId: Int, diagnosis: String) {
    val msg = "patient %d diagnosis %s".format(patientId, diagnosis)
    // ruleid: log.android.logcat
    Log.i(L2, msg)
}

data class PaymentCard(val holder: String, val cardNumber: String, val expiry: String)

// S09: a field of an object written to a file.
fun s09ObjectField(context: Context, card: PaymentCard) {
    // ruleid: storage.jvm.file
    File(context.filesDir, "last-card.txt").writeText(card.cardNumber)
    // ok: storage.jvm.file
    File(context.filesDir, "last-expiry.txt").writeText(card.expiry)
}

// S10: a map key says what its value is.
fun s10MapKey(client: OkHttpClient, value: String) {
    val json = JSONObject(mapOf("ssn" to value))
    val request = Request.Builder().url("https://kyc.partner.example/verify")
        .post(json.toString().toRequestBody("application/json".toMediaType())).build()
    // ruleid: net.jvm.okhttp
    client.newCall(request).execute()
}

// auditLog is a helper several scenarios call.
fun auditLog(event: String, detail: String) {
    // ruleid: log.android.logcat
    Log.i(L2, "audit $event $detail")
}

// S11: the value is logged by a helper.
fun s11Helper(email: String) {
    auditLog("login", email)
}

class Patient(val id: Int, private val mrn: String) {
    fun getMedicalRecordNumber(): String = mrn
}

// S12: a getter returns the value.
fun s12Getter(patient: Patient) {
    // ruleid: sdk.sentry.capture
    Sentry.captureMessage("record opened ${patient.getMedicalRecordNumber()}")
}

// S13: the value is replaced on one path before it is logged.
fun s13Overwritten(email: String, anonymous: Boolean) {
    var shown = email
    if (anonymous) {
        shown = "anonymous"
        // ok: log.android.logcat
        Log.i(L2, "comment by $shown")
        return
    }
    // ruleid: log.android.logcat
    Log.i(L2, "comment by $shown")
}

// S14: an API key sent to the service it authenticates to.
fun s14CredentialToItsService(client: OkHttpClient, apiKey: String) {
    val request = Request.Builder().url("https://api.payments.example/v1/balance")
        .header("Authorization", "Bearer $apiKey").build()
    // ok: net.jvm.okhttp
    client.newCall(request).execute()
}

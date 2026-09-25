// Examples for the Kotlin/Java logging sinks (internal/rules/builtin/jvm.yaml).
package examples.logging

import android.util.Log
import org.slf4j.LoggerFactory
import timber.log.Timber

class SignupLogging {
    private val logger = LoggerFactory.getLogger(SignupLogging::class.java)

    fun logcat(email: String, orderId: Long) {
        // ruleid: log.android.logcat
        Log.d(TAG, "signup $email")
        // ok: log.android.logcat
        Log.d(TAG, "order $orderId")
    }

    fun timber(phoneNumber: String) {
        // ruleid: log.android.timber
        Timber.i("OTP sent to %s", phoneNumber)
    }

    fun stdout(dateOfBirth: String) {
        // ruleid: log.jvm.stdout
        println("dob=$dateOfBirth")
    }

    fun slf4j(email: String) {
        // ruleid: log.jvm.logger
        logger.info("login failed for {}", email)
    }

    companion object {
        private const val TAG = "Signup"
    }
}

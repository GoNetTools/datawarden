// Examples for the logging sinks in Java.
package examples;

import android.util.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Logging {
    private static final String TAG = "Logging";
    private static final Logger log = LoggerFactory.getLogger(Logging.class);

    void logcat(String email, long orderId) {
        // ruleid: log.android.logcat
        Log.e(TAG, "signup failed for " + email);
        // ok: log.android.logcat
        Log.e(TAG, "order " + orderId);
    }

    void slf4j(String phoneNumber) {
        // ruleid: log.jvm.logger
        log.info("otp sent to {}", phoneNumber);
    }

    void stdout(String email) {
        // ruleid: log.jvm.stdout
        System.out.println("email=" + email);
    }
}

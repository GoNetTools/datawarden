// Examples for the logging sinks in Java.
package examples;

import android.util.Log;
import java.util.logging.Level;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

class Logging {
    private static final String TAG = "Logging";
    private static final Logger log = LoggerFactory.getLogger(Logging.class);
    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(Logging.class);
    private static final java.util.logging.Logger jul = java.util.logging.Logger.getLogger("examples");
    private static final org.apache.log4j.Logger legacy = org.apache.log4j.Logger.getLogger(Logging.class);
    private static final org.apache.commons.logging.Log commons = org.apache.commons.logging.LogFactory.getLog(Logging.class);
    private static final org.jboss.logging.Logger jboss = org.jboss.logging.Logger.getLogger(Logging.class);
    private static final System.Logger system = System.getLogger("examples");
    // A logger of a type datawarden does not know matches by its name.
    private final AppLogger auditLogger = AppLogger.get("audit");

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

    void log4j2(String email, String cardNumber, long orderId) {
        // ruleid: log.jvm.logger
        LOGGER.fatal("signup failed for {}", email);
        // ruleid: log.jvm.logger
        LOGGER.log(org.apache.logging.log4j.Level.DEBUG, "card {}", cardNumber);
        // ruleid: log.jvm.logger
        LOGGER.printf(org.apache.logging.log4j.Level.INFO, "user %s", email);
        // ok: log.jvm.logger
        LOGGER.trace("order {}", orderId);
    }

    void javaUtilLogging(String email, String nationalId) {
        // ruleid: log.jvm.logger
        jul.finer("lookup " + email);
        // ruleid: log.jvm.logger
        jul.config("id " + nationalId);
        // ruleid: log.jvm.logger
        jul.logp(Level.INFO, "Logging", "javaUtilLogging", "user {0}", email);
    }

    void log4j1AndCommons(String email, String phoneNumber) {
        // ruleid: log.jvm.logger
        legacy.warn("no account for " + email);
        // ruleid: log.jvm.logger
        commons.error("otp failed for " + phoneNumber);
    }

    void jbossAndSystemLogger(String email, String dateOfBirth) {
        // ruleid: log.jvm.logger
        jboss.infof("signup %s", email);
        // ruleid: log.jvm.logger
        system.log(System.Logger.Level.INFO, "dob " + dateOfBirth);
    }

    void tinylog(String email) {
        // ruleid: log.jvm.logger
        org.tinylog.Logger.info("signup {}", email);
    }

    void namedLogger(String email) {
        // ruleid: log.jvm.logger
        auditLogger.info("login {}", email);
    }

    void fluent(String email, String phoneNumber, long orderId) {
        // ruleid: log.jvm.fluent
        log.atInfo().addArgument(email).log("signup {}");
        // ruleid: log.jvm.fluent
        log.atWarn().addKeyValue("phone", phoneNumber).log("otp failed");
        // ruleid: log.jvm.fluent
        log.atDebug().log("user {}", email);
        // ok: log.jvm.fluent
        log.atInfo().log("order {}", orderId);
    }

    void mdc(String email, String requestId) {
        // ruleid: log.jvm.mdc
        MDC.put("user", email);
        // ruleid: log.jvm.mdc
        ThreadContext.put("user", email);
        // ok: log.jvm.mdc
        MDC.put("requestId", requestId);
    }

    void stackTrace(String email) {
        try {
            lookup(email);
        } catch (IllegalStateException e) {
            // ruleid: log.jvm.stack_trace
            e.printStackTrace();
        }
    }

    void lookup(String email) {
        throw new IllegalStateException("no account for " + email);
    }

    void stdout(String email, String phoneNumber) {
        // ruleid: log.jvm.stdout
        System.out.println("email=" + email);
        // ruleid: log.jvm.stdout
        System.err.format("phone=%s%n", phoneNumber);
    }
}

// Lombok generates the "log" field; the annotation says which logger it is.
@Slf4j
class LombokLogging {
    void signup(String email) {
        // ruleid: log.jvm.logger
        log.info("signup {}", email);
    }
}

// Level 1: a value reaches a sink in the method it arrives in.
package scenarios;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Level1Basic {
    private static final Logger log = LoggerFactory.getLogger(Level1Basic.class);

    // S01: a parameter logged as it arrives.
    void s01DirectParam(String email) {
        // ruleid: log.jvm.logger
        log.info("signup {}", email);
    }

    // S02: a local variable named for what it holds.
    void s02LocalVariable(String raw) {
        String phoneNumber = raw.trim();
        // ruleid: log.jvm.logger
        log.info("otp sent to {}", phoneNumber);
    }

    // S03: values that are not personal data, and names that only look like it.
    void s03NotPersonal(String orderId, int itemCount, boolean emailEnabled, String phoneFormatter) {
        // ok: log.jvm.logger
        log.info("order {} items {}", orderId, itemCount);
        // ok: log.jvm.logger
        log.info("email notifications {}", emailEnabled);
        // ok: log.jvm.logger
        log.info("format {}", phoneFormatter);
    }

    // S04: a credential logged.
    void s04Credential(String username, String password) {
        // ruleid: log.jvm.logger
        log.info("login {}/{}", username, password);
    }

    static String maskEmail(String email) {
        int at = email.indexOf('@');
        return at > 0 ? email.charAt(0) + "***" + email.substring(at) : "***";
    }

    // S05: masked before it is logged.
    void s05Masked(String email) {
        // ok: log.jvm.logger
        log.info("reset link sent to {}", maskEmail(email));
    }

    // S06: a hash of personal data still identifies the person.
    void s06HashedPersonal(String email) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(email.getBytes(StandardCharsets.UTF_8));
        // ruleid: log.jvm.logger
        log.info("lookup key {}", digest);
    }

    // S07: a hashed password is safe to log.
    void s07HashedCredential(String password) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
        // ok: log.jvm.logger
        log.info("password fingerprint {}", digest);
    }
}

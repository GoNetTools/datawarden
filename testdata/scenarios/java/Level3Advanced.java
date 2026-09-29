// Level 3: collections, lambdas, exceptions, consent checks, sanitizers
// and objects that keep what their constructor was given.
package scenarios;

import android.os.Bundle;
import com.google.firebase.analytics.FirebaseAnalytics;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Level3Advanced {
    private static final Logger log = LoggerFactory.getLogger(Level3Advanced.class);
    private final FirebaseAnalytics firebaseAnalytics;

    Level3Advanced(FirebaseAnalytics firebaseAnalytics) {
        this.firebaseAnalytics = firebaseAnalytics;
    }

    static class Member {
        String name;
        String email;
    }

    // S15: a collection built in a loop.
    void s15Collection(List<Member> members) {
        List<String> emails = new ArrayList<>();
        for (Member m : members) {
            emails.add(m.email);
        }
        // ruleid: log.jvm.logger
        log.info("newsletter to {}", String.join(",", emails));
    }

    // S16: a lambda captures the value.
    void s16Lambda(String phoneNumber, List<String> codes) {
        Consumer<String> send = code -> {
            // ruleid: log.jvm.logger
            log.info("sms {} {}", phoneNumber, code);
        };
        codes.forEach(send);
    }

    static class AccountNotFoundException extends RuntimeException {
        AccountNotFoundException(String message) {
            super(message);
        }
    }

    void lookupAccount(String email) {
        throw new AccountNotFoundException("no account for " + email);
    }

    // S17: the value travels in an exception.
    void s17Exception(String email) {
        try {
            lookupAccount(email);
        } catch (AccountNotFoundException e) {
            // ruleid: log.jvm.logger
            log.warn("lookup failed: {}", e.getMessage());
        }
    }

    interface Consents {
        boolean hasAnalyticsConsent();
    }

    // S18: analytics sent only after a consent check. Reported with the check;
    // accepted when policy.consent_guarded lists third_party.
    void s18ConsentGuarded(String email, Consents consents) {
        if (!consents.hasAnalyticsConsent()) {
            return;
        }
        Bundle params = new Bundle();
        params.putString("email", email);
        // ruleid: sdk.firebase.analytics
        firebaseAnalytics.logEvent("sign_up", params);
    }

    static boolean isMasked(String value) {
        return value.contains("***");
    }

    // S19: logged only when a check says it is already masked.
    void s19Sanitizer(String email) {
        if (isMasked(email)) {
            // ok: log.jvm.logger
            log.info("contact {}", email);
        }
    }

    static class Session {
        private final String userId;
        private final String accessToken;

        Session(String userId, String token) {
            this.userId = userId;
            this.accessToken = token;
        }

        // S20: the constructor stores the value, another method logs it.
        void debug() {
            // ruleid: log.jvm.logger
            log.info("session user={} token={}", userId, accessToken);
        }
    }

    void s20ConstructorField(String userId, String token) {
        new Session(userId, token).debug();
    }
}

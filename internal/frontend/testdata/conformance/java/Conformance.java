// Frontend conformance programs for Java. Every language implements the
// same scenarios (see TestFrontendConformance in internal/app).
package conformance;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

class User {
    long id;
    String email;
    String contact;

    String contactEmail() {
        return email;
    }
}

record Profile(String email, String nickname) {}

class Conformance {
    // scenario: param
    void param(String email) {
        // ruleid: log.jvm.stdout
        System.out.println(email);
    }

    // scenario: local
    void local(String email) {
        String x = email;
        // ruleid: log.jvm.stdout
        System.out.println(x);
    }

    // scenario: concat
    void concat(String email) {
        String msg = "signup " + email;
        // ruleid: log.jvm.stdout
        System.out.println(msg);
    }

    // scenario: field
    void field(User u) {
        // ruleid: log.jvm.stdout
        System.out.println(u.email);
    }

    // scenario: getter
    void getter(User u) {
        // ruleid: log.jvm.stdout
        System.out.println(u.contactEmail());
    }

    // scenario: key
    void key(String value) {
        Map<String, String> payload = new HashMap<>();
        payload.put("email", value);
        // ruleid: log.jvm.stdout
        System.out.println(payload);
    }

    void logIt(String v) {
        // ruleid: log.jvm.stdout
        System.out.println(v);
    }

    // scenario: call-arg
    void callArg(String email) {
        logIt(email);
    }

    String normalize(String s) {
        return s.trim().toLowerCase();
    }

    // scenario: call-return
    void callReturn(String email) {
        // ruleid: log.jvm.stdout
        System.out.println(normalize(email));
    }

    // scenario: closure
    void closure(String email, List<String> items) {
        items.forEach(it -> {
            // ruleid: log.jvm.stdout
            System.out.println(it + " " + email);
        });
    }

    // scenario: field-store
    void fieldStore(String phoneNumber) {
        User u = new User();
        u.contact = phoneNumber;
        // ruleid: log.jvm.stdout
        System.out.println(u.contact);
    }

    // scenario: collection
    void collection(String email) {
        List<String> xs = new ArrayList<>();
        xs.add(email);
        // ruleid: log.jvm.stdout
        System.out.println(xs);
    }

    // scenario: object
    void whole(Profile p) {
        // ruleid: log.jvm.stdout
        System.out.println(p);
    }

    String maskEmail(String e) {
        return e.substring(0, 1) + "***";
    }

    // scenario: masked
    void masked(String email) {
        // ok: log.jvm.stdout
        System.out.println(maskEmail(email));
    }

    // scenario: not-pii
    void notPii(User u, long orderId, int count) {
        // ok: log.jvm.stdout
        System.out.println(u.id + " " + orderId + " " + count);
    }

    // scenario: negative-context
    void negativeContext(int phoneCount, String emailTemplate) {
        // ok: log.jvm.stdout
        System.out.println(phoneCount + " " + emailTemplate);
    }

    // scenario: overwritten
    void overwritten(String email) {
        String x = email;
        x = "anonymous";
        // ok: log.jvm.stdout
        System.out.println(x);
    }

    // scenario: remasked
    void remasked(String email) {
        email = maskEmail(email);
        // ok: log.jvm.stdout
        System.out.println(email);
    }

    // scenario: branch-merge
    void branchMerge(String email, boolean verbose) {
        String x = "anonymous";
        if (verbose) {
            x = email;
        }
        // ruleid: log.jvm.stdout
        System.out.println(x);
    }

    // scenario: loop-carried
    void loopCarried(String email, java.util.List<String> items) {
        String x = "anonymous";
        for (String item : items) {
            // ruleid: log.jvm.stdout
            System.out.println(x);
            x = email;
        }
    }

    // scenario: mutated-later
    void mutatedLater(String email) {
        List<String> xs = new ArrayList<>();
        // ok: log.jvm.stdout
        System.out.println(xs);
        xs.add(email);
    }

    // scenario: early-return
    void earlyReturn(String email, boolean invalid) {
        String x = "anonymous";
        if (invalid) {
            x = email;
            // ruleid: log.jvm.stdout
            System.out.println(x);
            return;
        }
        // ok: log.jvm.stdout
        System.out.println(x);
    }

    // scenario: break-exit
    void breakExit(String email, List<String> items) {
        String x = "anonymous";
        for (String item : items) {
            if (item.isEmpty()) {
                x = email;
                break;
            }
        }
        // ruleid: log.jvm.stdout
        System.out.println(x);
    }

    // scenario: continue-skip
    void continueSkip(String email, List<String> items) {
        for (String item : items) {
            String x = "anonymous";
            if (item.isEmpty()) {
                x = email;
                continue;
            }
            // ok: log.jvm.stdout
            System.out.println(x);
        }
    }

    // scenario: snapshot
    void snapshot(String email) {
        List<String> items = new ArrayList<>();
        String msg = "items=" + items;
        items.add(email);
        // ok: log.jvm.stdout
        System.out.println(msg);
    }

    static final boolean VERBOSE_LOGGING = false;

    // scenario: constant-condition
    void constantCondition(String email) {
        if (VERBOSE_LOGGING) {
            // ok: log.jvm.stdout
            System.out.println(email);
        }
    }

    // scenario: field-across-methods
    static class Mailbox {
        private final String addr;
        Mailbox(String email) { this.addr = email; }
        void announce() {
            // ruleid: log.jvm.stdout
            System.out.println("sending to " + addr);
        }
    }

    void fieldAcrossMethods(String email) { new Mailbox(email).announce(); }

    // scenario: dynamic-dispatch
    interface Channel { void deliver(String to); }

    static class SmsChannel implements Channel {
        public void deliver(String to) {
            // ruleid: log.jvm.stdout
            System.out.println("sms " + to);
        }
    }

    void dynamicDispatch(Channel c, String email) { c.deliver(email); }

    // scenario: exception
    void exception(String email) {
        try {
            throw new IllegalArgumentException("unknown user " + email);
        } catch (IllegalArgumentException e) {
            // ruleid: log.jvm.stdout
            System.out.println(e.getMessage());
        }
    }

    // scenario: lambda-variable
    void lambdaVariable(String email) {
        java.util.function.Consumer<String> show = v -> {
            // ruleid: log.jvm.stdout
            System.out.println(v);
        };
        show.accept(email);
    }
}

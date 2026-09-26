// Language constructs the Java frontend must lower. Unlike the shared
// scenarios in Conformance.java, these are specific to Java.
package conformance;

import java.util.List;

class Session {
    static String lastEmail = "";
}

class Constructs {
    private String contactEmail;

    void ifElse(String email, boolean verbose) {
        if (verbose) {
            // ruleid: log.jvm.stdout
            System.out.println("verbose " + email);
        } else {
            // ok: log.jvm.stdout
            System.out.println("quiet");
        }
    }

    void switchStatement(String email, int kind) {
        switch (kind) {
            case 1:
                // ruleid: log.jvm.stdout
                System.out.println(email);
                break;
            default:
                // ok: log.jvm.stdout
                System.out.println("none");
        }
    }

    void loops(List<String> emails) {
        for (String e : emails) {
            // ruleid: log.jvm.stdout
            System.out.println(e);
        }
        for (int i = 0; i < emails.size(); i++) {
            // ruleid: log.jvm.stdout
            System.out.println(emails.get(i));
        }
    }

    void tryCatch(String email) {
        try {
            send(email);
        } catch (RuntimeException e) {
            // ruleid: log.jvm.stdout
            System.out.println("failed for " + email);
        }
    }

    void send(String to) {
        // ruleid: log.jvm.stdout
        System.out.println("mail to " + to);
    }

    void ternary(String email, boolean masked) {
        String shown = masked ? "***" : email;
        // ruleid: log.jvm.stdout
        System.out.println(shown);
    }

    void builder(String email) {
        StringBuilder sb = new StringBuilder();
        sb.append("user=").append(email);
        // The second append's receiver is the first call's result, which
        // is sb itself.
        // ruleid: log.jvm.stdout
        System.out.println(sb.toString());
    }

    void format(String email) {
        // ruleid: log.jvm.stdout
        System.out.println(String.format("user=%s", email));
    }

    void staticField(String email) {
        Session.lastEmail = email;
        // ruleid: log.jvm.stdout
        System.out.println(Session.lastEmail);
    }

    void thisField(String email) {
        this.contactEmail = email;
        // ruleid: log.jvm.stdout
        System.out.println(this.contactEmail);
    }

    void streams(List<String> emails) {
        emails.stream().map(String::trim).forEach(e -> {
            // ruleid: log.jvm.stdout
            System.out.println(e);
        });
    }

    void varargs(String email) {
        // ruleid: log.jvm.stdout
        System.out.printf("%s %s%n", "user", email);
    }

    void switchOverwrites(String email, int kind) {
        String x = email;
        switch (kind) {
            case 1: x = "one"; break;
            default: x = "other";
        }
        // ok: log.jvm.stdout
        System.out.println(x);
    }

    void elseOverwrites(String email, boolean c) {
        String x = email;
        if (c) { x = "a"; } else { x = "b"; }
        // ok: log.jvm.stdout
        System.out.println(x);
    }

    void catchSeesEarlierValue(String email) {
        String x = email;
        try {
            x = "cleared";
            Integer.parseInt(x);
        } catch (NumberFormatException e) {
            // ruleid: log.jvm.stdout
            System.out.println(x);
        }
    }

    void switchFallsThrough(String email, int kind) {
        String x = "anonymous";
        switch (kind) {
            case 1:
                x = email;
            case 2:
                // case 1 has no break, so it continues here.
                // ruleid: log.jvm.stdout
                System.out.println(x);
                break;
            default:
                // ok: log.jvm.stdout
                System.out.println(x);
        }
    }

    void labeledBreak(String email, List<List<String>> rows) {
        String x = "anonymous";
        outer:
        for (List<String> row : rows) {
            for (String cell : row) {
                if (cell.isEmpty()) {
                    x = email;
                    break outer;
                }
            }
            x = "reset";
        }
        // ruleid: log.jvm.stdout
        System.out.println(x);
    }
}

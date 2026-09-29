// Level 2: a value is formatted, stored in an object or a map, or passed
// to a helper before it reaches a sink.
package scenarios;

import io.sentry.Sentry;
import java.io.FileWriter;
import java.io.IOException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Level2Intermediate {
    private static final Logger log = LoggerFactory.getLogger(Level2Intermediate.class);
    private static final MediaType JSON = MediaType.get("application/json");
    private final OkHttpClient client = new OkHttpClient();

    // S08: health data formatted into a message.
    void s08Formatted(int patientId, String diagnosis) {
        String msg = String.format("patient %d diagnosis %s", patientId, diagnosis);
        // ruleid: log.jvm.logger
        log.info(msg);
    }

    static class PaymentCard {
        String holder;
        String cardNumber;
        String expiry;
    }

    // S09: a field of an object written to a file.
    void s09ObjectField(PaymentCard card) throws IOException {
        FileWriter cardFile = new FileWriter("last-card.txt");
        // ruleid: storage.jvm.file
        cardFile.write(card.cardNumber);
        FileWriter expiryFile = new FileWriter("last-expiry.txt");
        // ok: storage.jvm.file
        expiryFile.write(card.expiry);
    }

    // S10: a map key says what its value is.
    void s10MapKey(String value) throws IOException {
        JSONObject json = new JSONObject();
        json.put("ssn", value);
        Request request = new Request.Builder().url("https://kyc.partner.example/verify")
            .post(RequestBody.create(json.toString(), JSON)).build();
        // ruleid: net.jvm.okhttp
        client.newCall(request).execute();
    }

    // auditLog is a helper several scenarios call.
    void auditLog(String event, String detail) {
        // ruleid: log.jvm.logger
        log.info("audit {} {}", event, detail);
    }

    // S11: the value is logged by a helper.
    void s11Helper(String email) {
        auditLog("login", email);
    }

    static class Patient {
        private final int id;
        private final String mrn;

        Patient(int id, String mrn) {
            this.id = id;
            this.mrn = mrn;
        }

        String getMedicalRecordNumber() {
            return mrn;
        }
    }

    // S12: a getter returns the value.
    void s12Getter(Patient patient) {
        // ruleid: sdk.sentry.capture
        Sentry.captureMessage("record opened " + patient.getMedicalRecordNumber());
    }

    // S13: the value is replaced on one path before it is logged.
    void s13Overwritten(String email, boolean anonymous) {
        String shown = email;
        if (anonymous) {
            shown = "anonymous";
            // ok: log.jvm.logger
            log.info("comment by {}", shown);
            return;
        }
        // ruleid: log.jvm.logger
        log.info("comment by {}", shown);
    }

    // S14: an API key sent to the service it authenticates to.
    void s14CredentialToItsService(String apiKey) throws IOException {
        Request request = new Request.Builder().url("https://api.payments.example/v1/balance")
            .header("Authorization", "Bearer " + apiKey).build();
        // ok: net.jvm.okhttp
        client.newCall(request).execute();
    }
}

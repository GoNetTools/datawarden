// Level 4: dynamic dispatch, listeners kept in fields, deep objects,
// multi-layer pipelines, device storage and ordering.
package scenarios;

import android.content.SharedPreferences;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

class Level4Complex {
    private static final Logger log = LoggerFactory.getLogger(Level4Complex.class);
    private final OkHttpClient client = new OkHttpClient();

    interface Notifier {
        void notify(String to, String body);
    }

    static class SmsNotifier implements Notifier {
        @Override
        public void notify(String to, String body) {
            // ruleid: log.jvm.logger
            log.info("sms to={} body={}", to, body);
        }
    }

    static class PushNotifier implements Notifier {
        int sent;

        @Override
        public void notify(String to, String body) {
            sent++;
        }
    }

    // S21: the value reaches the sink through an interface call.
    void s21Dispatch(Notifier notifier, String phoneNumber) {
        notifier.notify(phoneNumber, "your code is ready");
    }

    static class EventBus {
        private Consumer<String> onSignup;

        void subscribe(Consumer<String> handler) {
            this.onSignup = handler;
        }

        void publish(String email) {
            onSignup.accept(email);
        }
    }

    // S22: a listener kept in a field runs later with the value.
    void s22StoredCallback(EventBus bus, String emailAddress) {
        bus.subscribe(e -> {
            // ruleid: log.jvm.logger
            log.info("welcome mail queued for {}", e);
        });
        bus.publish(emailAddress);
    }

    static class Contact { String homeAddress; }
    static class Customer { Contact contact; }
    static class Order {
        String id;
        Customer customer;
    }

    // S23: a value three fields deep.
    void s23DeepField(Order order) throws IOException {
        Request label = new Request.Builder().url("https://shipping.partner.example/labels")
            .post(new FormBody.Builder().add("to", order.customer.contact.homeAddress).build()).build();
        // ruleid: net.jvm.okhttp
        client.newCall(label).execute();
        Request status = new Request.Builder().url("https://shipping.partner.example/status")
            .post(new FormBody.Builder().add("order", order.id).build()).build();
        // ok: net.jvm.okhttp
        client.newCall(status).execute();
    }

    static class ProfileRepo {
        private final Connection conn;

        ProfileRepo(Connection conn) {
            this.conn = conn;
        }

        void save(String userId, String dateOfBirth) throws SQLException {
            PreparedStatement st = conn.prepareStatement("UPDATE profiles SET dob = ? WHERE id = ?");
            st.setString(1, dateOfBirth);
            st.setString(2, userId);
            st.executeUpdate();
        }
    }

    class ProfileService {
        private final ProfileRepo repo;

        ProfileService(ProfileRepo repo) {
            this.repo = repo;
        }

        void update(String userId, String dob) throws SQLException, IOException {
            repo.save(userId, dob);
            Request request = new Request.Builder().url("https://age-check.partner.example/v1")
                .post(new FormBody.Builder().add("dob", dob).build()).build();
            // ruleid: net.jvm.okhttp
            client.newCall(request).execute();
        }
    }

    // S24: request → service → repository and partner.
    @PostMapping("/profile")
    void s24Pipeline(ProfileService svc, @RequestParam String userId, @RequestParam String dateOfBirth) throws SQLException, IOException {
        svc.update(userId, dateOfBirth);
    }

    // S25: a session token persisted on the device.
    void s25DeviceStorage(SharedPreferences prefs, String sessionToken) {
        // ruleid: storage.android.shared_prefs
        prefs.edit().putString("session", sessionToken).apply();
    }

    // S26: an object logged before the value is added to it, then after.
    void s26Ordering(String email) {
        Map<String, String> payload = new HashMap<>();
        payload.put("source", "web");
        // ok: log.jvm.logger
        log.info("payload {}", payload);
        payload.put("email", email);
        // ruleid: log.jvm.logger
        log.info("payload {}", payload);
    }
}

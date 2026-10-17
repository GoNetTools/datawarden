// Examples for the network and file sinks in Java.
package examples;

import io.sentry.Sentry;
import java.io.FileWriter;
import java.io.IOException;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

class Network {
    private final OkHttpClient client = new OkHttpClient();

    void okhttp(String phoneNumber) throws IOException {
        Request request = new Request.Builder().url("https://crm.vendor.example/leads?phone=" + phoneNumber).build();
        // ruleid: net.jvm.okhttp
        client.newCall(request).execute();
    }

    // The body goes into the request through the builder's post(), which
    // the api rules describe (api.jvm.okhttp_request_builder).
    void okhttpBody(String nationalId) throws IOException {
        RequestBody body = RequestBody.create(nationalId, MediaType.get("text/plain"));
        Request request = new Request.Builder().url("https://kyc.vendor.example/verify").post(body).build();
        // ruleid: net.jvm.okhttp
        client.newCall(request).execute();
    }

    // The length of a value carries none of it (api.jvm.string_none).
    void length(String email) throws IOException {
        Request request = new Request.Builder().url("https://crm.vendor.example/stats?len=" + email.length()).build();
        // ok: net.jvm.okhttp
        client.newCall(request).execute();
    }

    void file(String email) throws IOException {
        FileWriter writer = new FileWriter("export.csv");
        // ruleid: storage.jvm.file
        writer.write(email);
    }

    void sentry(String email) {
        // ruleid: sdk.sentry.capture
        Sentry.addBreadcrumb("reset requested by " + email);
    }
}

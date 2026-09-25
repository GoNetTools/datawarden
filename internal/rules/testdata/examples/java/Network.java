// Examples for the network and file sinks in Java.
package examples;

import io.sentry.Sentry;
import java.io.FileWriter;
import java.io.IOException;
import okhttp3.OkHttpClient;
import okhttp3.Request;

class Network {
    private final OkHttpClient client = new OkHttpClient();

    void okhttp(String phoneNumber) throws IOException {
        Request request = new Request.Builder().url("https://crm.vendor.example/leads?phone=" + phoneNumber).build();
        // ruleid: net.jvm.okhttp
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

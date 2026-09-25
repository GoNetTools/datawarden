// Examples for the Java transform rules. Hashes and Base64 are not safe
// transforms by default; encryption is.
package examples;

import android.util.Base64;
import android.util.Log;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import org.apache.commons.codec.digest.DigestUtils;

class Transforms {
    private static final String TAG = "Transforms";

    void digest(String email) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        // ruleid: xform.jvm.digest
        byte[] hash = md.digest(email.getBytes());
        // ruleid: log.android.logcat
        Log.d(TAG, "key " + hash);
    }

    void commons(String phoneNumber) {
        // ruleid: xform.jvm.commons_digest
        String key = DigestUtils.sha256Hex(phoneNumber);
        // ruleid: log.android.logcat
        Log.d(TAG, "key " + key);
    }

    void cipher(Cipher cipher, String email) throws Exception {
        // ruleid: xform.jvm.cipher
        byte[] sealed = cipher.doFinal(email.getBytes());
        // ok: log.android.logcat
        Log.d(TAG, "sealed " + sealed);
    }

    void base64(String email) {
        // ruleid: xform.jvm.base64
        String encoded = Base64.encodeToString(email.getBytes(), Base64.NO_WRAP);
        // ruleid: log.android.logcat
        Log.d(TAG, "encoded " + encoded);
    }
}

package com.vulnshop.profile;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

// Vulnerable by design: see CheckoutActivity.kt.
public class ProfileSync {
    private static final String TAG = "ProfileSync";
    private final Context context;

    public ProfileSync(Context context) {
        this.context = context;
    }

    public void publish(String email, String dateOfBirth) {
        Intent intent = new Intent("com.vulnshop.PROFILE_UPDATED");
        intent.putExtra("email", email);
        // LEAK: email in an implicit broadcast any app can receive.
        context.sendBroadcast(intent);
        // LEAK: date of birth to logcat.
        Log.d(TAG, "profile dob " + dateOfBirth);
    }

    public void refresh(long profileId) {
        // SAFE: profile id only.
        Log.d(TAG, "refreshing profile " + profileId);
    }
}

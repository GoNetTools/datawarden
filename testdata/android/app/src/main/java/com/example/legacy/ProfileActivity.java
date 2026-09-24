package com.example.legacy;

import android.util.Log;
import io.sentry.Sentry;
import javax.persistence.Column;
import javax.persistence.Entity;

@Entity
class Profile {
    @Column(name = "email") private String mail;
    private String bio;
    public String getMail() { return this.mail; }
}

public class ProfileActivity {
    private static final String TAG = "Profile";

    public void show(Profile profile, String hoTen) {
        String greeting = "Xin chao " + hoTen;
        Log.d(TAG, greeting);
        Sentry.setExtra("mail", profile.getMail());
        System.out.println("bio: " + profile.getBio());
        send(profile.getMail());
    }

    private void send(String value) {
        Log.e(TAG, "sending " + value);
    }
}

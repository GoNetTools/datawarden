// Examples for the Android source APIs, called as Java getters.
package examples;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.location.Location;
import android.location.LocationManager;
import android.telephony.TelephonyManager;
import android.util.Log;

class Sources {
    private static final String TAG = "Sources";

    void ownNumber(TelephonyManager tm) {
        // ruleid: src.android.phone_number
        String line = tm.getLine1Number();
        // ruleid: log.android.logcat
        Log.i(TAG, "prefill " + line);
    }

    void deviceId(TelephonyManager telephony) {
        // ruleid: src.android.device_ids
        String imei = telephony.getImei();
        // ruleid: log.android.logcat
        Log.i(TAG, "device " + imei);
    }

    void accounts(AccountManager accountManager) {
        // ruleid: src.android.accounts
        Account[] accounts = accountManager.getAccounts();
        // ruleid: log.android.logcat
        Log.i(TAG, "accounts " + accounts[0].name);
    }

    void coordinates(Location location) {
        // ruleid: src.android.location
        double lat = location.getLatitude();
        // ruleid: log.android.logcat
        Log.i(TAG, "lat " + lat);
    }
}

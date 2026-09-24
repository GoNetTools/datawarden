package com.example.app.data

import android.content.Context
import android.util.Log
import com.google.firebase.crashlytics.FirebaseCrashlytics
import io.sentry.Sentry
import io.sentry.protocol.User

class CustomerRepo(private val context: Context) {
    private val prefs = context.getSharedPreferences("app", Context.MODE_PRIVATE)

    fun save(customer: Customer) {
        Log.d(TAG, "saving ${customer.contact}")
        Sentry.setUser(User().apply { email = customer.email })
        FirebaseCrashlytics.getInstance().setCustomKey("cccd", customer.cccd)
        prefs.edit().putString("phone", customer.contact).apply()
        Log.i(TAG, "saved id=${customer.id} nick=${customer.nickname}")
        audit(customer.contact.maskPhone())
    }

    fun audit(msg: String) {
        Log.w(TAG, msg)
    }

    companion object {
        private const val TAG = "CustomerRepo"
    }
}

fun String.maskPhone(): String = take(3) + "*******"

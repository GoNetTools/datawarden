package com.example.app.ui

import com.example.app.data.Customer
import com.example.app.data.CustomerRepo
import com.google.firebase.analytics.FirebaseAnalytics
import androidx.core.os.bundleOf

class SignupViewModel(private val repo: CustomerRepo, private val analytics: FirebaseAnalytics) {
    fun submit(fullName: String, phoneNumber: String, birthDate: String) {
        analytics.logEvent("sign_up", bundleOf("phone" to phoneNumber, "method" to "sms"))
        val customer = Customer(1, phoneNumber, null, "", fullName)
        repo.save(customer)
        track(birthDate)
    }

    private fun track(dob: String) {
        println("dob=$dob")
    }
}

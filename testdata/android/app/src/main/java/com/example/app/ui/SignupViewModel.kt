package com.example.app.ui

import com.example.app.data.Customer
import com.example.app.data.CustomerRepo
import com.google.firebase.analytics.FirebaseAnalytics
import androidx.core.os.bundleOf

class SignupViewModel(private val repo: CustomerRepo, private val analytics: FirebaseAnalytics) {
    fun submit(hoTen: String, soDienThoai: String, ngaySinh: String) {
        analytics.logEvent("sign_up", bundleOf("sdt" to soDienThoai, "method" to "phone"))
        val customer = Customer(1, soDienThoai, null, "", hoTen)
        repo.save(customer)
        track(ngaySinh)
    }

    private fun track(dob: String) {
        println("dob=$dob")
    }
}

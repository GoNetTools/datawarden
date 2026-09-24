package com.example.app.data

import androidx.room.ColumnInfo
import androidx.room.Entity

@Entity(tableName = "customers")
data class Customer(
    val id: Long,
    @ColumnInfo(name = "phone_number") val contact: String,
    val email: String?,
    val cccd: String,
    val nickname: String,
)

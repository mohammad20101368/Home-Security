package com.example.smssender

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.telephony.SmsManager
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat

class MainActivity : AppCompatActivity() {

    private val phoneNumber = "+989355414622" // شماره ادمین اصلی

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // درخواست مجوز ارسال SMS
        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.SEND_SMS)
            != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.SEND_SMS), 1)
        }

        findViewById<Button>(R.id.buttonOn).setOnClickListener { sendSMS("on") }
        findViewById<Button>(R.id.buttonLPIR).setOnClickListener { sendSMS("LPIR") }
        findViewById<Button>(R.id.buttonLGAS).setOnClickListener { sendSMS("LGAS") }
        findViewById<Button>(R.id.buttonLASER).setOnClickListener { sendSMS("LASER") }
        findViewById<Button>(R.id.buttonStop).setOnClickListener { sendSMS("STOP") }
        findViewById<Button>(R.id.buttonOff).setOnClickListener { sendSMS("OFF") }
    }

    private fun sendSMS(message: String) {
        val smsManager = SmsManager.getDefault()
        smsManager.sendTextMessage(phoneNumber, null, message, null, null)
        Toast.makeText(this, "Message sent: $message", Toast.LENGTH_SHORT).show()
    }
}

package com.lib.paymentlibrary

import Enum.DukptKeyType
import Enum.DukptVersion
import Utils.byteArrayToHexString
import Utils.hexStringToByteArray
import Utils.trim
import android.content.Context
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.material3.Button
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.lib.payment.Algorithm.Dukpt
import com.lib.paymentlibrary.ui.theme.PaymentLibraryTheme
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val context = this // Initialize context here
        enableEdgeToEdge()
        setContent {
            PaymentLibraryTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    TestButton(
                        context = context, // Pass context here
                        modifier = Modifier.padding(innerPadding)
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalStdlibApi::class)
@Composable
fun TestButton(context: Context, modifier: Modifier = Modifier) {
    Box(
        modifier = modifier
            .fillMaxSize()
            .padding(top = 16.dp) // Add padding from the top
    ) {
        Button(
            onClick = {
                val bdkHex = "0123456789ABCDEFFEDCBA9876543210" // 16-byte BDK
                val ksnHex = "FFFF9876543210E00004" // KSN (using first 8 bytes)

                // Convert BDK and KSN from Hex to ByteArray
                val bdk = hexStringToByteArray(bdkHex)
                val ksn = hexStringToByteArray(ksnHex)

                val dukpt = Dukpt(context)
                val dukptInt = dukpt.initializeDukpt(
                    dukptVersion = DukptVersion.DUKPT_2009,
                    keyType = DukptKeyType.IPEK,
                    key = bdk,
                    ksn = ksn
                )
                if(dukptInt.isError()){
                    Log.e("Dukpt","isError ${dukptInt.toError()}")
                }
                if(dukptInt.isSuccess()){
                    Log.e("Dukpt","isSuccess ${dukptInt.toData()}")
                    var result = dukpt.encryptData(hexStringToByteArray("1234"))
                    Log.e("Dukpt","encrypted Data = $result")
                }

            },
            modifier = Modifier
                .align(Alignment.TopCenter) // Align button to the top center
                .fillMaxWidth(0.5f) // Optionally make the button half the screen width
        ) {
            Text(text = "Test")
        }
    }

}

@Preview(showBackground = true)
@Composable
fun TestButtonPreview() {
    PaymentLibraryTheme {
        // We can't pass context in previews, so omit the parameter here
    }
}

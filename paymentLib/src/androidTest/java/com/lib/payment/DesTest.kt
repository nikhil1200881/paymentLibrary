package com.lib.payment

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.lib.payment.Algorithm.Dukpt
import com.lib.payment.Algorithm.IDukpt
import des.Des
import des.DesType
import des.EncryptionMode
import des.PaddingMode
import junit.framework.Assert.assertEquals
import junit.framework.Assert.assertTrue
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

class DesTest {

    @Test
    fun testEncryption_with_IncorrectPaddingMode() {
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.DES)
        val data = "FABC12"
        val key = "1111111111111111"
        val paddingMode = PaddingMode.NONE

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        if (result.isError()) {
            output = true
            errorCode = result.toError().errorCode
        } else {
            output = false
        }

        assertTrue("Expected output to be true when encryption fails with unknown DesType",output )
        assertNotNull("Error code should not be null",errorCode )
    }

    @Test
    fun testDesEncryption_with_incorrect_key(){
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.DES)
        val data = "FABC12"
        val key = "111111111111111" // Incorrect key length - 15 characters
        val paddingMode = PaddingMode.NONE

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        if (result.isError()) {
            output = true
            errorCode = result.toError().errorCode
        } else {
            output = false
        }

        assertTrue("Expected output to be true when encryption fails with incorrect key length",output )
        assertNotNull("Error code should not be null",errorCode )
    }

    @Test
    fun testDesEncryption_with_incorrect_data(){
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.DES)
        val data = ""
        val key = "1111111111111111"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = EncryptionMode.UNKNOWN

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        if (result.isError()) {
            output = true
            errorCode = result.toError().errorCode
        } else {
            output = false
        }

        assertTrue("Expected output to be true when encryption fails with incorrect encryptionMode",output )
        assertNotNull("Error code should not be null",errorCode )
    }

    @Test
    fun testDesEncryption_with_unsupportedEncryptionMode(){
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.DES)
        val data = "12345678"
        val key = "2b71790f9fa47810"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = EncryptionMode.OFB_64

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        if (result.isError()) {
            output = true
            errorCode = result.toError().errorCode
        } else {
            output = false
        }

        assertTrue("Expected output to be true when encryption fails with unsupported encryptionMode",output )
        assertNotNull("Error code should not be null",errorCode )
    }

    @Test
    fun testDesEncryption_with_correctData_ecb_mode(){
        var output: Boolean?

        val des = Des(DesType.DES)
        val data = "12345678"
        val key = "C1D0F8FB4958670D"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = EncryptionMode.ECB
        var encryptionResult: String?
        var expectedData = "2b71790f9fa47810"

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        if (result.isError()) {
            output = false
            encryptionResult = ""
        } else {
            output = true
            encryptionResult = result.toData().encryptedData
        }

        assertTrue("Expected output to be true when encryption Success",output )
        assertEquals(expectedData,encryptionResult)
    }

    @Test
    fun testDesEncryption_with_correctData_cbc_mode(){
        var output: Boolean?

        val des = Des(DesType.DES)
        val data = "12345678"
        val key = "C1D0F8FB4958670D"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = EncryptionMode.CBC
        var encryptionResult: String?
        var expectedData = "2b71790f9fa47810"

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        if (result.isError()) {
            output = false
            encryptionResult = ""
        } else {
            output = true
            encryptionResult = result.toData().encryptedData
        }

        assertTrue("Expected output to be true when encryption Success",output )
        assertEquals(expectedData,encryptionResult)
    }

}
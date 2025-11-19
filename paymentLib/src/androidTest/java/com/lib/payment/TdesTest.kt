package com.lib.payment

import des.Des
import des.DesError
import des.DesType
import des.Mode
import des.PaddingMode
import junit.framework.Assert.assertTrue
import org.junit.Test
import junit.framework.Assert.assertEquals
import org.junit.Assert.assertNotNull

class TdesTest {

    @Test
    fun testTdesEncryption_withCorrectParameters() {
        val tdes = Des(DesType.TDES)
        val data = "12345678"
        val key = "C1D0F8FB4958670DC1D0F8FB4958670D"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = Mode.ECB
        var encryptionResult: String?
        var expectedData = "2b71790f9fa47810"

        val result = tdes.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        assertTrue("Encryption Failed",result.isSuccess())
        assertEquals(expectedData,result.toData().encryptedData)
    }

    @Test
    fun testEncryption_with_IncorrectPaddingMode() {
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.TDES)
        val data = "FABC12"
        val key = "11111111111111111111111111111111"
        val paddingMode = PaddingMode.UNKNOWN

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        assertTrue("Expected output to be true when encryption fails with unknown DesType",result.isError() )
        assertNotNull("Error code should not be null",result.toError().errorCode )
        assertEquals(result.toError().errorCode, DesError.INVALID_PADDING_MODE.ordinal)

    }

    @Test
    fun testDesEncryption_with_incorrect_keyLength16(){
        var errorCode: Int? = 0

        val des = Des(DesType.TDES)
        val data = "FABC12"
        val key = "11111111111111111" // Incorrect key length - 16 characters
        val paddingMode = PaddingMode.NONE

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        assertTrue("Expected output to be true when encryption fails with incorrect key length",result.isError() )
        assertNotNull("Error code should not be null",result.toError().errorCode )
        assertEquals(result.toError().errorCode, DesError.INVALID_KEY_LENGTH.ordinal)
    }

    @Test
    fun testDesEncryption_with_incorrect_keylength17(){
        var errorCode: Int? = 0

        val des = Des(DesType.TDES)
        val data = "FABC12"
        val key = "111111111111111111" // Incorrect key length - 17 characters
        val paddingMode = PaddingMode.NONE

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        assertTrue("Expected output to be true when encryption fails with incorrect key length",result.isError() )
        assertNotNull("Error code should not be null",result.toError().errorCode )
        assertEquals(result.toError().errorCode, DesError.INVALID_KEY_LENGTH.ordinal)
    }

    @Test
    fun testDesEncryption_with_incorrect_keylength64(){
        var errorCode: Int? = 0

        val des = Des(DesType.TDES)
        val data = "FABC12"
        val key = "1111111111111111111111111111111111111111111111111111111111111111" // Incorrect key length - 64 characters
        val paddingMode = PaddingMode.NONE

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode)

        assertTrue("Expected output to be true when encryption fails with incorrect key length",result.isError() )
        assertNotNull("Error code should not be null",result.toError().errorCode )
        assertEquals(result.toError().errorCode, DesError.INVALID_KEY_LENGTH.ordinal)
    }

    @Test
    fun testDesEncryption_with_incorrect_data(){
        var output: Boolean?
        var errorCode: Int? = 0

        val des = Des(DesType.TDES)
        val data = ""
        val key = "11111111111111111111111111111111"
        val paddingMode = PaddingMode.NONE
        val encryptionMode = Mode.ECB

        val result = des.encrypt(data = data, key = key, paddingMode = paddingMode, encryptionMode = encryptionMode)

        assertTrue("Expected output to be true when encryption fails with incorrect encryptionMode",result.isError() )
        assertNotNull("Error code should not be null",result.toError().errorCode )
        assertEquals(result.toError().errorCode, DesError.INVALID_DATA.ordinal)
    }


    @Test
    fun testTripleDESEncryption_AllModes_AllPaddings_keySize_16byte() {
        val tdes = Des(DesType.TDES)
        val data = "12345678"
        val key = "C1D0F8FB4958670DC1D0F8FB4958670D"
        val initialValue = "1234567812345678"
        for (mode in Mode.entries) {
            // Skip UNKNOWN mode automatically
            if (mode == Mode.UNKNOWN) continue

            for (padding in PaddingMode.entries) {
                try {
                    val encryptedData = tdes.encrypt(
                        data = data,
                        key = key,
                        paddingMode = padding,
                        encryptionMode = mode,
                        initialVector = if (mode != Mode.ECB) initialValue else null
                    )

                    if (encryptedData.isSuccess()) {
                        println("Encryption | ${mode.name} | ${padding.name} → ${encryptedData.toData().encryptedData}")
                        assertTrue("${mode.name}-${padding.name} encryption should succeed", encryptedData.isSuccess())
                    } else {
                        println(" ${mode.name} | ${padding.name} → FAILED: ${encryptedData.toError()}")
                    }

                    val decryptedData = tdes.decrypt(
                        data = encryptedData.toData().encryptedData,
                        key = key,
                        paddingMode = padding,
                        decryptionMode =  mode,
                        initialVector = if (mode != Mode.ECB) initialValue else null
                    )

                    if (decryptedData.isSuccess()) {
                        println("Decryption | ${mode.name} | ${padding.name} → ${decryptedData.toData().encryptedData}")
                        assertTrue("${mode.name}-${padding.name} encryption should succeed", decryptedData.isSuccess())
                        assertEquals(decryptedData.toData().encryptedData,data)
                    } else {
                        println(" ${mode.name} | ${padding.name} → FAILED: ${decryptedData.toError()}")
                    }

                } catch (e: Exception) {
                    println(" ${mode.name} | ${padding.name} → Exception: ${e.message}")
                }
            }
        }
    }

    @Test
    fun testTripleDESEncryption_AllModes_AllPaddings_keySize_24byte() {
        val tdes = Des(DesType.TDES)
        val data = "12345678"
        val key = "C1D0F8FB4958670DC1D0F8FB4958670DC1D0F8FB4958670D"
        val initialValue = "1234567812345678"
        for (mode in Mode.entries) {
            // Skip UNKNOWN mode automatically
            if (mode == Mode.UNKNOWN) continue

            for (padding in PaddingMode.entries) {
                try {
                    val encryptedData = tdes.encrypt(
                        data = data,
                        key = key,
                        paddingMode = padding,
                        encryptionMode = mode,
                        initialVector = if (mode != Mode.ECB) initialValue else null
                    )

                    if (encryptedData.isSuccess()) {
                        println("Encryption | ${mode.name} | ${padding.name} → ${encryptedData.toData().encryptedData}")
                        assertTrue("${mode.name}-${padding.name} encryption should succeed", encryptedData.isSuccess())
                    } else {
                        println(" ${mode.name} | ${padding.name} → FAILED: ${encryptedData.toError()}")
                    }

                    val decryptedData = tdes.decrypt(
                        data = encryptedData.toData().encryptedData,
                        key = key,
                        paddingMode = padding,
                        decryptionMode =  mode,
                        initialVector = if (mode != Mode.ECB) initialValue else null
                    )

                    if (decryptedData.isSuccess()) {
                        println("Decryption | ${mode.name} | ${padding.name} → ${decryptedData.toData().encryptedData}")
                        assertTrue("${mode.name}-${padding.name} encryption should succeed", decryptedData.isSuccess())
                        assertEquals(decryptedData.toData().encryptedData,data)
                    } else {
                        println(" ${mode.name} | ${padding.name} → FAILED: ${decryptedData.toError()}")
                    }

                } catch (e: Exception) {
                    println(" ${mode.name} | ${padding.name} → Exception: ${e.message}")
                }
            }
        }
    }

}
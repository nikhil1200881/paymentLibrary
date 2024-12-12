package com.lib.payment.Algorithm

import Enum.DerivationPurpose
import Enum.DukptVersion
import Enum.KeyType
import Enum.KeyUsage
import Utils.byteArrayToHexString
import Utils.hexStringToByteArray
import Utils.intToBytes
import Utils.shiftRight
import Utils.validateDukptAesParameters
import android.util.Log
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class DukptAes: IDukptAes {

    var dukptAesOutput: DukptAesOutput? = null

    override fun initializeDukptAes(
        ksn: ByteArray,
        dukptAesKey: ByteArray,
        keyType: KeyType,
        dukptVersion: DukptVersion,
        workingKeyType: KeyType
    ):DukptResult<DukptAesOutput> {

        val validationResult =
            validateDukptAesParameters(dukptKey = dukptAesKey, dukptKsn = ksn, keyType = keyType)
        if (!validationResult.isSuccess()) {
            return validationResult
        }

        val initialKeyIdHex = toHex(ksnToInitialKeyId(ksn))

        val initialKey = deriveInitialKey(dukptAesKey, keyType, ksn)
        val ksnCounter = getKsnCounter(toHex(ksn))
        val ksnForWorkingKeys =
            toByteArray(initialKeyIdHex + toHex(intToBytes(ksnCounter)))


        Log.d("Test_ksn","ksn = ${toHex(ksnForWorkingKeys)}")
        // Variables for each enum variable
        val keyEncryptionKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._KeyEncryptionKey,
            workingKeyType, ksnForWorkingKeys
        )


        val pinEncryptionKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._PINEncryption,
            workingKeyType, ksnForWorkingKeys
        )

        val macGenerationKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._MessageAuthenticationGeneration,
            workingKeyType, ksnForWorkingKeys
        )

        val macVerificationKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._MessageAuthenticationVerification,
            workingKeyType, ksnForWorkingKeys
        )

        val macBothWaysKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._MessageAuthenticationBothWays,
            workingKeyType, ksnForWorkingKeys
        )

        val dataEncryptKey = hostDeriveWorkingKey(
            initialKey,keyType, KeyUsage._DataEncryptionEncrypt,
            workingKeyType, ksnForWorkingKeys
        )

        val dataDecryptKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._DataEncryptionDecrypt,
            workingKeyType, ksnForWorkingKeys
        )

        val dataBothWaysKey = hostDeriveWorkingKey(
            initialKey, keyType, KeyUsage._DataEncryptionBothWays,
            workingKeyType, ksnForWorkingKeys
        )

        dukptAesOutput = DukptAesOutput(
            dukptAes_bdk = toHex(dukptAesKey),
            dukptAes_initalKey = toHex(initialKey!!),
            ksnCounter = ksnCounter.toString(16),
            ksn = toHex(ksn),
            keyEncryptionKey = toHex(keyEncryptionKey),
            pinEncryptionKey = toHex(pinEncryptionKey),
            macGenerationKey = toHex(macGenerationKey),
            macVerificationKey =toHex(macVerificationKey),
            macBothWaysKey =toHex(macBothWaysKey),
            dataEncryptKey =toHex(dataEncryptKey),
            dataDecryptKey =toHex(dataDecryptKey),
            dataBothWaysKey =toHex(dataBothWaysKey),

        )
        return DukptResult.Success(dukptAesOutput!!)

    }

    private fun getKsnCounter(ksn: String): Long {
        val counter = ksn.drop(16)
        return counter.toLong()
    }

    @Throws(Exception::class)
    fun deriveInitialKey(bdk: ByteArray?, keyType: KeyType?, initialKeyId: ByteArray?): ByteArray? {
        val derivationData: ByteArray = createDerivationData(
            DerivationPurpose._InitialKey,
            KeyUsage._KeyDerivationInitialKey,
            keyType!!,
            initialKeyId!!,
            0
        )
        return deriveKey(bdk, keyType, derivationData)
    }

    fun createDerivationData(
        derivationPurpose: DerivationPurpose,
        keyUsage: KeyUsage,
        keyType: KeyType,
        initialKeyID: ByteArray,
        counter: Long
    ): ByteArray {
        val derivationData = ByteArray(16)
        derivationData[0] = 0x01
        derivationData[1] = 0x01

        if (keyUsage === KeyUsage._KeyEncryptionKey) {
            derivationData[2] = 0x00
            derivationData[3] = 0x02
        } else if (keyUsage === KeyUsage._PINEncryption) {
            derivationData[2] = 0x10 // for 0x16 replace with 0x10
            derivationData[3] = 0x00
        } else if (keyUsage === KeyUsage._MessageAuthenticationGeneration) {
            derivationData[2] = 0x20 // for 0x32 replace with 0x20
            derivationData[3] = 0x00
        } else if (keyUsage === KeyUsage._MessageAuthenticationVerification) {
            derivationData[2] = 0x20 // for 0x32 replace with 0x20
            derivationData[3] = 0x01
        } else if (keyUsage === KeyUsage._MessageAuthenticationBothWays) {
            derivationData[2] = 0x20 // for 0x32 replace with 0x20
            derivationData[3] = 0x02
        } else if (keyUsage === KeyUsage._DataEncryptionEncrypt) {
            derivationData[2] = 0x30 // for 0x48 replace with 0x30
            derivationData[3] = 0x00
        } else if (keyUsage === KeyUsage._DataEncryptionDecrypt) {
            derivationData[2] = 0x30 // for 0x48 replace with 0x30
            derivationData[3] = 0x01
        } else if (keyUsage === KeyUsage._DataEncryptionBothWays) {
            derivationData[2] = 0x30 // for 0x48 replace with 0x30
            derivationData[3] = 0x02
        } else if (keyUsage === KeyUsage._KeyDerivation) {
            derivationData[2] = -128
            derivationData[3] = 0x00
        } else if (keyUsage === KeyUsage._KeyDerivationInitialKey) {
            derivationData[2] = -128
            derivationData[3] = 0x01
        } else {
            return byteArrayOf()
        }

        if (keyType === KeyType._2TDEA) {
            derivationData[4] = 0x00
            derivationData[5] = 0x00
        } else if (keyType === KeyType._3TDEA) {
            derivationData[4] = 0x00
            derivationData[5] = 0x01
        } else if (keyType === KeyType._AES128) {
            derivationData[4] = 0x00
            derivationData[5] = 0x02
        } else if (keyType === KeyType._AES192) {
            derivationData[4] = 0x00
            derivationData[5] = 0x03
        } else if (keyType === KeyType._AES256) {
            derivationData[4] = 0x00
            derivationData[5] = 0x04
        } else {
            return byteArrayOf()
        }

        if (keyType === KeyType._2TDEA) {
            derivationData[6] = 0x00
            derivationData[7] = -128
        } else if (keyType === KeyType._3TDEA) {
            derivationData[6] = 0x00
            derivationData[7] = -64
        } else if (keyType === KeyType._AES128) {
            derivationData[6] = 0x00
            derivationData[7] = -128
        } else if (keyType === KeyType._AES192) {
            derivationData[6] = 0x00
            derivationData[7] = -64
        } else {
            derivationData[6] = 0x01
            derivationData[7] = 0x00
        }

        if (derivationPurpose === DerivationPurpose._InitialKey) {
            derivationData[8] = initialKeyID[0]
            derivationData[9] = initialKeyID[1]
            derivationData[10] = initialKeyID[2]
            derivationData[11] = initialKeyID[3]
            derivationData[12] = initialKeyID[4]
            derivationData[13] = initialKeyID[5]
            derivationData[14] = initialKeyID[6]
            derivationData[15] = initialKeyID[7]
        } else if (derivationPurpose === DerivationPurpose._DerivationOrWorkingKey) {
            derivationData[8] = initialKeyID[4]
            derivationData[9] = initialKeyID[5]
            derivationData[10] = initialKeyID[6]
            derivationData[11] = initialKeyID[7]

            val value: ByteArray = intToBytes(counter)
            derivationData[12] = value[0]
            derivationData[13] = value[1]
            derivationData[14] = value[2]
            derivationData[15] = value[3]
        } else {
            return byteArrayOf()
        }

        return derivationData
    }

    @Throws(java.lang.Exception::class)
    fun deriveKey(
        derivationKey: ByteArray?,
        keyType: KeyType?,
        derivationData: ByteArray?
    ): ByteArray {
        val L: Int = keyLength(keyType)
        val result: ByteArray =
            encryptAes(derivationKey, derivationData)
        val n = L / 8
        return Arrays.copyOfRange(result, 0, n)
    }

    fun keyLength(keyType: KeyType?): Int {
        return when (keyType) {
            KeyType._2TDEA, KeyType._AES128 -> 128
            KeyType._3TDEA, KeyType._AES192 -> 192
            KeyType._AES256 -> 256
            else -> 0
        }
    }

    @Throws(java.lang.Exception::class)
    fun encryptAes(key: ByteArray?, data: ByteArray?): ByteArray {
        val iv = IvParameterSpec(ByteArray(16))
        val encryptKey = SecretKeySpec(key, "AES")
        val encryptor = Cipher.getInstance("AES/CBC/NoPadding")
        encryptor.init(Cipher.ENCRYPT_MODE, encryptKey, iv)
        return encryptor.doFinal(data)
    }

    fun ksnToInitialKeyId(ksn: ByteArray): ByteArray {
        val initialKeyId = ByteArray(8)

        if (ksn.size == 10) {
            // Legacy KSN
            // +-----------------------+---------------------+
            // | Legacy Initial key ID | Transaction Counter |
            // |       (59 bits)       |      (21 bits)      |
            // +-----------------------+---------------------+
            //
            // It is recommended that legacy initial key ID starting with the byte “0E” SHOULD be
            // reserved for use with KSN compatibility mode
            //
            // Key Set ID = 0E11111111
            // Device ID = 22222
            // Initial Key ID = 0E1111111122222
            // Legacy KSN = 0E111111112222200000
            // Internal KSN = 00E111111112222200000000
            if (ksn[0].toInt() != 0x0E) {
                // Just warn, it is only a recommendation
                println("Warning: legacy initial key id does not start with 0E")
            }

            // Legacy KSN packs key id in first 59 bits, remaining 21 bits are the counter, copy
            // just bytes that contain the key id
            System.arraycopy(ksn, 0, initialKeyId, 0, 8)

            // need to zero counter bits in the last byte that is border between key id and counter
            initialKeyId[7] = (initialKeyId[7].toInt() and 0xE0).toByte()

            // Pad first 4 bits with zero per KSN Compatibility Mode
            return shiftRight(initialKeyId, 4)
        } else if (ksn.size == 12) {
            // New 96-bit KSN
            // +-----------------------+---------------------+
            // |    Initial key ID     | Transaction Counter |
            // |       (64 bits)       |      (32 bits)      |
            // +-----------------------+---------------------+
            //
            // Example 123456789012345600000001
            System.arraycopy(ksn, 0, initialKeyId, 0, 8)
            return initialKeyId
        } else {
            throw UnsupportedOperationException("Unsupported IKSN length: " + ksn.size)
        }
    }

    @Throws(java.lang.Exception::class)
    fun hostDeriveWorkingKey(
        initialKey: ByteArray?, deriveKeyType: KeyType?, workingKeyUsage: KeyUsage?,
        workingKeyType: KeyType?, ksn: ByteArray
    ): ByteArray {
        val isLegacy = ksn.size == 10

        // set the most significant bit to one and all other bits to zero
        // legacy mode uses 21-bit counter, otherwise counter is 32-bit
        var mask = if (isLegacy) 1L shl 21 else 1L shl 31
        var workingCounter: Long = 0
        val transactionCounter: Long = ksnToCounter(ksn)
        val initialKeyID: ByteArray = ksnToInitialKeyId(ksn)
        var derivationData: ByteArray
        var derivationKey = initialKey

        while (mask > 0) {
            if ((mask and transactionCounter) != 0L) {
                workingCounter = workingCounter or mask
                derivationData =createDerivationData(
                    DerivationPurpose._DerivationOrWorkingKey,
                    KeyUsage._KeyDerivation, deriveKeyType!!, initialKeyID, workingCounter
                )
                derivationKey = deriveKey(
                    derivationKey,
                    deriveKeyType,
                    derivationData
                )
            }
            mask = mask shr 1
        }

        derivationData = createDerivationData(
            DerivationPurpose._DerivationOrWorkingKey,
            workingKeyUsage!!, workingKeyType!!, initialKeyID, transactionCounter
        )
        return deriveKey(
            derivationKey,
            workingKeyType,
            derivationData
        )
    }
    fun ksnToCounter(ksn: ByteArray): Long {
        // Destination is java-size long
        val counterBytes = ByteArray(8)

        if (ksn.size == 10) {
            // Legacy KSN, counter is right 21 bits
            // Position of the byte where key id and counter meet
            val borderBytePos = counterBytes.size - 3
            // Copy right 24 bits to the end of a 32 bit buffer
            System.arraycopy(ksn, 7, counterBytes, borderBytePos, 3)
            // Clear left 3 bits of the 24 bits copied to preserve just 21 bits
            counterBytes[borderBytePos] = (counterBytes[borderBytePos].toInt() and 0x1F).toByte()
        } else if (ksn.size == 12) {
            // New 96-bit KSN, counter is right 32 bits
            System.arraycopy(ksn, 8, counterBytes, counterBytes.size - 4, 4)
        } else {
            throw java.lang.UnsupportedOperationException("Unsupported IKSN length: " + ksn.size)
        }

        val buffer = ByteBuffer.wrap(counterBytes)
        return buffer.getLong()
    }

    fun toByteArray(s: String): ByteArray {
        val sanitized = s.replace(" ", "")
        val len = sanitized.length
        require(len % 2 == 0) { "Input string must have an even length" }

        return ByteArray(len / 2) { i ->
            val high = sanitized[i * 2].digitToIntOrNull(16) ?: error("Invalid character in input string")
            val low = sanitized[i * 2 + 1].digitToIntOrNull(16) ?: error("Invalid character in input string")
            ((high shl 4) + low).toByte()
        }
    }

    /**
     *
     * Converts a byte array into a hexadecimal string (Big-Endian).
     *
     * @return A representation of a hexadecimal number without any leading qualifiers such as "0x" or "x".
     */
    fun toHex(bytes: ByteArray): String {
        val bi = BigInteger(1, bytes)
        return String.format("%0" + (bytes.size shl 1) + "X", bi)
    }


}
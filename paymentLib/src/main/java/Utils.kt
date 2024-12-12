import Enum.DukptError
import Enum.DukptKeyType
import Enum.DukptVersion
import Enum.KeyType
import com.lib.payment.Algorithm.DukptAesOutput
import com.lib.payment.Algorithm.DukptInput
import com.lib.payment.Algorithm.DukptResult
import java.nio.ByteBuffer
import java.nio.ByteOrder

object Utils {

    fun ByteArray.toHexString(): String {
        return joinToString("") { "%02x".format(it) }
    }
    fun hexStringToByteArray(hex: String): ByteArray {
        return ByteArray(hex.length / 2) { i ->
            ((Character.digit(hex[i * 2], 16) shl 4) + Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
    }
    fun byteArrayToHexString(bytes: ByteArray): String {
        return bytes.joinToString("") { String.format("%02X", it) }
    }

    fun trim(array: ByteArray?, length: Int): ByteArray {
        val trimmedArray = ByteArray(length)
        System.arraycopy(array, 0, trimmedArray, 0, length)
        return trimmedArray
    }

    fun concat(
        array1: ByteArray?, beginIndex1: Int, length1: Int, array2: ByteArray?,
        beginIndex2: Int, length2: Int
    ): ByteArray {
        val concatArray = ByteArray(length1 + length2)
        System.arraycopy(array1, beginIndex1, concatArray, 0, length1)
        System.arraycopy(array2, beginIndex2, concatArray, length1, length2)
        return concatArray
    }

    fun concat(array1: ByteArray, array2: ByteArray): ByteArray {
        val concatArray = ByteArray(array1.size + array2.size)
        System.arraycopy(array1, 0, concatArray, 0, array1.size)
        System.arraycopy(array2, 0, concatArray, array1.size, array2.size)
        return concatArray
    }
    fun validateDukptParameters(
        dukptKey: ByteArray,
        dukptKsn: ByteArray,
        keyType: DukptKeyType,
        dukptVersion: DukptVersion
    ): DukptResult<DukptInput> {
        if (dukptKey.isEmpty()) {
            return DukptResult.Error(DukptError.EMPTY_KEY.error)
        }
        if (dukptKsn.isEmpty()) {
            return DukptResult.Error(DukptError.EMPTY_KSN.error)
        }

        when (dukptVersion) {
            DukptVersion.DUKPT_TDES -> {
                when {
                    dukptKsn.size != 10 -> {
                        return DukptResult.Error(DukptError.INVALID_KSN_LENGTH.error)
                    }
                    dukptKey.size != 16 -> {
                        return DukptResult.Error(DukptError.INVALID_KEY_LENGTH.error)
                    }
                }
            }
            else -> {
                return DukptResult.Error(DukptError.UNKNOWN.error)  // Correct reference here
            }
        }

        return DukptResult.Success(
            DukptInput()
        )
    }

    fun intToBytes(x: Long): ByteArray {
        val buffer = ByteBuffer.allocate(java.lang.Long.SIZE / java.lang.Byte.SIZE)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putLong(x)
        val longArray = buffer.array()
        val intArray = ByteArray(Integer.SIZE / java.lang.Byte.SIZE)
        System.arraycopy(longArray, intArray.size, intArray, 0, intArray.size)
        return intArray
    }
    fun shiftRight(byteArray: ByteArray, shiftBitCount: Int): ByteArray {
        val shiftMod = shiftBitCount % 8
        val carryMask = (0xFF shl (8 - shiftMod)).toByte()
        val offsetBytes = (shiftBitCount / 8)

        var sourceIndex: Int
        for (i in byteArray.indices.reversed()) {
            sourceIndex = i - offsetBytes
            if (sourceIndex < 0) {
                byteArray[i] = 0
            } else {
                val src = byteArray[sourceIndex]
                var dst = ((0xff and src.toInt()) ushr shiftMod).toByte()
                if (sourceIndex - 1 >= 0) {
                    dst =
                        (dst.toInt() or (byteArray[sourceIndex - 1].toInt() shl (8 - shiftMod) and carryMask.toInt())).toByte()
                }
                byteArray[i] = dst
            }
        }
        return byteArray
    }
    fun validateDukptAesParameters(
        dukptKey: ByteArray,
        dukptKsn: ByteArray,
        keyType: KeyType
    ): DukptResult<DukptAesOutput> {
        // Validate KSN
        if (dukptKsn.isEmpty()) {
            return DukptResult.Error(DukptError.EMPTY_KEY.error)
        }
        if (dukptKsn.size !in listOf(10, 12)) {
            return DukptResult.Error(DukptError.INVALID_KSN_LENGTH.error)
        }

        // Validate Key
        if (dukptKey.isEmpty()) {
            return DukptResult.Error(DukptError.EMPTY_KEY.error)
        }

        val expectedKeyLength = when (keyType) {
            KeyType._AES128 -> 16
            KeyType._AES192 -> 24
            KeyType._AES256 -> 32
            else -> null // Unsupported key type
        }

        if (expectedKeyLength == null || dukptKey.size != expectedKeyLength) {
            return DukptResult.Error(DukptError.INVALID_KEY_LENGTH.error)
        }

        // If all validations pass, return success
        return DukptResult.Success(DukptAesOutput())
    }

}
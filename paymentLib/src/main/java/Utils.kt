import Enum.DukptError
import Enum.DukptKeyType
import Enum.DukptVersion
import com.lib.payment.Algorithm.Dukpt
import com.lib.payment.Algorithm.DukptInput
import com.lib.payment.Algorithm.DukptResult
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

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
            DukptVersion.DUKPT_2009 -> {
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

     fun String.asciiToBcd(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()


}
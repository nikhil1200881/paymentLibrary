package des

import Enum.CryptoType
import Utils.asciiToBcd
import Utils.toHexString
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

class Des(private val desType: DesType): IDes {

    @RequiresApi(Build.VERSION_CODES.O)
    override fun encrypt(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        encryptionMode: Mode?,
        initialVector: String?
    ): DesResult<DesOutput> {
        return when(desType){
            DesType.DES -> performDesEncryption(data,key,paddingMode,initialVector,encryptionMode)
            DesType.TDES-> perfromTdesEncryption()
            DesType.UNKNOWN -> DesResult.Error(DesError.UNKNOWN_DES_TYPE.ordinal,DesError.UNKNOWN_DES_TYPE.name)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun decrypt(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        decryptionMode: Mode?,
        initialVector: String?
    ): DesResult<DesOutput> {
        return when(desType){
            DesType.DES -> performDesDecryption(data,key,paddingMode,initialVector,decryptionMode)
            DesType.TDES-> perfromTdesEncryption()
            DesType.UNKNOWN -> DesResult.Error(DesError.UNKNOWN_DES_TYPE.ordinal,DesError.UNKNOWN_DES_TYPE.name)
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun performDesEncryption(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        initialVector: String?,
        encryptionMode: Mode?,
    ): DesResult<DesOutput> {

        val validationResult = performDesValidation(
            data,
            key,
            paddingMode,
            encryptionMode,
            CryptoType.Encryption
        )
        if (validationResult.isError()) {
            return validationResult
        }

        return try {
            val algorithm = "DES"
            val encryptionModeDes = encryptionMode?.modeName
            val paddingName = paddingMode?.paddingName
            val transformation = "$algorithm/$encryptionModeDes/$paddingName"

            val ivSpec = if (!initialVector.isNullOrEmpty()) {
                IvParameterSpec(initialVector.toByteArray(Charsets.UTF_8))
            } else {
                IvParameterSpec(ByteArray(8)) // Default 8-byte zero IV
            }

            val keySpec = DESKeySpec(key?.asciiToBcd())
            val keyFactory = SecretKeyFactory.getInstance(algorithm)
            val desKey = keyFactory.generateSecret(keySpec)

            val cipher = Cipher.getInstance(transformation)
            if (encryptionMode == Mode.CBC) {
                cipher.init(Cipher.ENCRYPT_MODE, desKey, ivSpec)
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, desKey)
            }

            val encryptedBytes = cipher.doFinal(data?.toByteArray(Charsets.UTF_8))
            val encryptedHex = encryptedBytes.toHexString()

            Log.d("DES", "Encrypted Data = $encryptedHex")

            DesResult.Success(DesOutput(encryptedData = encryptedHex))

        } catch (e: InvalidKeyException) {
            Log.e("DES", "Invalid key: ${e.message}", e)
            DesResult.Error(DesError.INVALID_KEY_LENGTH.ordinal, e.message ?: "Invalid key")

        } catch (e: InvalidAlgorithmParameterException) {
            Log.e("DES", "Invalid IV parameter: ${e.message}", e)
            DesResult.Error(DesError.INVALID_IV.ordinal, e.message ?: "Invalid IV")

        } catch (e: NoSuchAlgorithmException) {
            Log.e("DES", "Algorithm not supported: ${e.message}", e)
            DesResult.Error(DesError.UNSUPPORTED_ALGORITHM.ordinal, e.message ?: "Algorithm not supported")

        } catch (e: NoSuchPaddingException) {
            Log.e("DES", "Padding not supported: ${e.message}", e)
            DesResult.Error(DesError.UNSUPPORTED_PADDING_MODE.ordinal, e.message ?: "Padding not supported")

        } catch (e: IllegalBlockSizeException) {
            Log.e("DES", "Illegal block size: ${e.message}", e)
            DesResult.Error(DesError.ILLEGAL_BLOCK_SIZE.ordinal, e.message ?: "Illegal block size")

        } catch (e: BadPaddingException) {
            Log.e("DES", "Bad padding: ${e.message}", e)
            DesResult.Error(DesError.BAD_PADDING.ordinal, e.message ?: "Bad padding")

        } catch (e: Exception) {
            Log.e("DES", "Unexpected error: ${e.message}", e)
            DesResult.Error(DesError.UNKNOWN_ERROR.ordinal, e.message ?: "Unknown error")
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun performDesDecryption(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        initialVector: String?,
        decryptionMode: Mode?
    ): DesResult<DesOutput> {

        // Step 1: Validate inputs
        val validationResult = performDesValidation(
            data,
            key,
            paddingMode,
            decryptionMode,
            CryptoType.Decryption
        )
        if (validationResult.isError()) {
            return validationResult
        }

        return try {
            val algorithm = "DES"
            val modeName = decryptionMode?.modeName
            val paddingName = paddingMode?.paddingName
            val transformation = "$algorithm/$modeName/$paddingName"

            val ivSpec = if (!initialVector.isNullOrEmpty()) {
                IvParameterSpec(initialVector.toByteArray(Charsets.UTF_8))
            } else {
                IvParameterSpec(ByteArray(8)) // Default zero IV
            }

            val keySpec = DESKeySpec(key?.asciiToBcd())
            val keyFactory = SecretKeyFactory.getInstance(algorithm)
            val desKey = keyFactory.generateSecret(keySpec)

            val cipher = Cipher.getInstance(transformation)
            if (decryptionMode == Mode.CBC) {
                cipher.init(Cipher.DECRYPT_MODE, desKey, ivSpec)
            } else {
                cipher.init(Cipher.DECRYPT_MODE, desKey)
            }

            val decryptedBytes = cipher.doFinal(data?.asciiToBcd())
            val decryptedText = decryptedBytes.toString(Charsets.UTF_8)

            Log.d("DES", "Decrypted Data = $decryptedText")

            DesResult.Success(DesOutput(encryptedData = decryptedText))

        } catch (e: InvalidKeyException) {
            Log.e("DES", "Invalid key: ${e.message}", e)
            DesResult.Error(DesError.INVALID_KEY_LENGTH.ordinal, e.message ?: "Invalid key")

        } catch (e: InvalidAlgorithmParameterException) {
            Log.e("DES", "Invalid IV parameter: ${e.message}", e)
            DesResult.Error(DesError.INVALID_IV.ordinal, e.message ?: "Invalid IV")

        } catch (e: NoSuchAlgorithmException) {
            Log.e("DES", "Algorithm not supported: ${e.message}", e)
            DesResult.Error(DesError.UNSUPPORTED_ALGORITHM.ordinal, e.message ?: "Algorithm not supported")

        } catch (e: NoSuchPaddingException) {
            Log.e("DES", "Padding not supported: ${e.message}", e)
            DesResult.Error(DesError.UNSUPPORTED_PADDING_MODE.ordinal, e.message ?: "Padding not supported")

        } catch (e: IllegalBlockSizeException) {
            Log.e("DES", "Illegal block size: ${e.message}", e)
            DesResult.Error(DesError.ILLEGAL_BLOCK_SIZE.ordinal, e.message ?: "Illegal block size")

        } catch (e: BadPaddingException) {
            Log.e("DES", "Bad padding: ${e.message}", e)
            DesResult.Error(DesError.BAD_PADDING.ordinal, e.message ?: "Bad padding")

        } catch (e: Exception) {
            Log.e("DES", "Unexpected error: ${e.message}", e)
            DesResult.Error(DesError.UNKNOWN_ERROR.ordinal, e.message ?: "Unknown error")
        }
    }


    private fun perfromTdesEncryption(): DesResult<DesOutput>{
        return DesResult.Error(DesError.UNKNOWN_DES_TYPE.ordinal,DesError.UNKNOWN_DES_TYPE.name)
    }

    private  fun performDesValidation(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        encryptionMode: Mode?,
        cryptoType: CryptoType?
    ): DesResult<DesOutput>{
        if (data.isNullOrEmpty()) {
            return DesResult.Error(
                DesError.INVALID_DATA.ordinal,
                DesError.INVALID_DATA.name
            )
        }

        if (key.isNullOrEmpty() || key.length != 16) {
            return DesResult.Error(
                DesError.INVALID_KEY_LENGTH.ordinal,
                DesError.INVALID_KEY_LENGTH.name
            )
        }

        if(paddingMode == PaddingMode.UNKNOWN){
            return DesResult.Error(
                DesError.INVALID_PADDING_MODE.ordinal,
                DesError.INVALID_PADDING_MODE.name
            )

        }

        if(encryptionMode == Mode.UNKNOWN){
            return DesResult.Error(
                DesError.INVALID_ENCRYPTION_MODE.ordinal,
                DesError.INVALID_ENCRYPTION_MODE.name
            )

        }
        if(!(encryptionMode == Mode.CBC || encryptionMode == Mode.ECB)){
            return DesResult.Error(
                DesError.UNSUPPORTED_ENCRYPTION_MODE.ordinal,
                DesError.UNSUPPORTED_ENCRYPTION_MODE.name
            )
        }

        if(cryptoType == CryptoType.Decryption){
            if(data.length!= key.length){
                return DesResult.Error(
                    DesError.INVALID_DATA.ordinal,
                    DesError.INVALID_DATA.name
                )
            }
        }

        val result = validateDesMode(desType,encryptionMode,paddingMode!!)
        if(result.isError()){
            return result
        }

        return DesResult.Success(DesOutput())

    }

    private fun validateDesMode(
        desType: DesType,
        encryptionMode: Mode,
        paddingMode: PaddingMode
    ): DesResult<DesOutput> {
        // Only validate DES-specific restrictions
        if (desType == DesType.DES) {

            // Unsupported padding combinations for DES/ECB
            val unsupportedForEcb = setOf(
                PaddingMode.RIJNDAEL,
                PaddingMode.SPACES,
                PaddingMode.ISO_10126,
                PaddingMode.ISO_7816_4,
                PaddingMode.ISO9797_1_PADDING_METHOD_1,
                PaddingMode.ISO9797_1_PADDING_METHOD_2
            )

            if (encryptionMode == Mode.ECB && paddingMode in unsupportedForEcb) {
                return DesResult.Error(
                    DesError.UNSUPPORTED_PADDING_MODE.ordinal,
                    "Unsupported padding mode for DES/ECB: ${paddingMode.name}"
                )
            }

            // Optional: you can also enforce unsupported paddings for CBC if needed
            val unsupportedForCbc = setOf(
                PaddingMode.RIJNDAEL, // AES-specific padding, not for DES
                PaddingMode.SPACES,
                PaddingMode.ISO9797_1_PADDING_METHOD_1,
                PaddingMode.ISO9797_1_PADDING_METHOD_2
            )

            if (encryptionMode == Mode.CBC && paddingMode in unsupportedForCbc) {
                return DesResult.Error(
                    DesError.UNSUPPORTED_PADDING_MODE.ordinal,
                    "Unsupported padding mode for DES/CBC: ${paddingMode.name}"
                )
            }
        }

        return DesResult.Success(DesOutput())
    }

}
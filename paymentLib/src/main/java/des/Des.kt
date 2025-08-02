package des

import Utils.toHexString
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec
import javax.crypto.spec.IvParameterSpec

class Des(private val desType: DesType): IDes {

    @RequiresApi(Build.VERSION_CODES.O)
    override fun encrypt(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        encryptionMode: EncryptionMode?,
        initialVector: String?
    ): DesResult<DesOutput> {
        return when(desType){
            DesType.DES -> performDesEncryption(data,key,paddingMode,initialVector,encryptionMode)
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
        encryptionMode: EncryptionMode?
    ): DesResult<DesOutput> {

        val validationResult = performDesValidation(data,key,paddingMode,encryptionMode)
        if(validationResult.isError()){
            return validationResult
        }

        val algorithm = "DES"
        val encryptionModeDes = encryptionMode?.encryptionModeName
        val paddingName = paddingMode?.paddingName
        val transformation = "$algorithm/$encryptionModeDes/$paddingName"
        val iv = if (!initialVector.isNullOrEmpty()) {
            IvParameterSpec(initialVector.toByteArray(Charsets.UTF_8))
        } else {
            IvParameterSpec(ByteArray(8))
        }


        val keySpec = DESKeySpec(key?.toByteArray())
        val keyFactory = SecretKeyFactory.getInstance(algorithm)
        val desKey = keyFactory.generateSecret(keySpec)

        val cipher = Cipher.getInstance(transformation)
        cipher.init(Cipher.ENCRYPT_MODE, desKey, iv)
        val encryptedData = cipher.doFinal(data?.toByteArray()).toHexString()
        Log.d("Des","Encrypted Data = $encryptedData")

       return DesResult.Success(DesOutput(encryptedData = encryptedData))
    }

    private fun perfromTdesEncryption(): DesResult<DesOutput>{
        return DesResult.Error(DesError.UNKNOWN_DES_TYPE.ordinal,DesError.UNKNOWN_DES_TYPE.name)
    }

    private  fun performDesValidation(
        data: String?,
        key: String?,
        paddingMode: PaddingMode?,
        encryptionMode: EncryptionMode?
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

        if(encryptionMode == EncryptionMode.UNKNOWN){
            return DesResult.Error(
                DesError.INVALID_ENCRYPTION_MODE.ordinal,
                DesError.INVALID_ENCRYPTION_MODE.name
            )

        }
        return DesResult.Success(DesOutput())

    }




}
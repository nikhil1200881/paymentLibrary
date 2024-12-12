package com.lib.payment.Algorithm

import Enum.DukptError
import Enum.DukptKeyType
import Enum.DukptVersion
import Utils.byteArrayToHexString
import Utils.concat
import Utils.hexStringToByteArray
import Utils.trim
import Utils.validateDukptParameters
import android.content.Context
import android.util.Log
import com.lib.payment.Algorithm.Constant.Companion.EMPTY_STRING
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Dukpt(context: Context):  IDukpt{

    private var dukptIpek: String = ""
    private var dukptksn: String = ""
    private var dukptBdk: String = ""
    private var dukptKeyType: DukptKeyType = DukptKeyType.UNKNOWN
    private var dukptDataKey: String = ""

    override fun initializeDukpt(
        dukptVersion: DukptVersion,
        keyType: DukptKeyType,
        key: ByteArray,
        ksn: ByteArray
    ): DukptResult<DukptInput> {
        val validationResult = validateDukptParameters(
            dukptKey = key,
            dukptKsn = ksn,
            keyType = keyType,
            dukptVersion = dukptVersion
        )
        if(!validationResult.isSuccess()){
            Log.d("Dukpt","Error = ${validationResult.toError()}")
            return validationResult
        }
        return when (dukptVersion) {
            DukptVersion.DUKPT_TDES -> dukptVersion2009(keyType, key, ksn)
            DukptVersion.DUKPT_AES -> TODO()
            DukptVersion.DUKPT_2017_C -> TODO()
            DukptVersion.UNKNOWN -> TODO()
            null -> TODO()
        }
    }

    override fun getIpek(): String {
        return dukptIpek
    }

    override fun getDataKey(): String {
        return dukptDataKey
    }

    override fun encryptData(plainData: ByteArray): String {
        if(plainData.isEmpty()){
            Log.e("encryptData","Empty plain data")
            return EMPTY_STRING
        }
        if(dukptDataKey.isEmpty()){
            Log.e("encryptData","Empty data key")
            return EMPTY_STRING
        }
        try {
            val dataKey = hexStringToByteArray( dukptDataKey)
            val result  = tdesEnc(plainData,dataKey)
            return byteArrayToHexString(result)
        }
        catch (ex: Exception){
            Log.d("Dukpt","encryptData exception ${ex.message}")
            return EMPTY_STRING
        }
        return EMPTY_STRING
    }

    override fun decryptData(encryptedData: ByteArray): String {
        TODO("Not yet implemented")
    }


    private fun dukptVersion2009(keyType: DukptKeyType?, dukptKey: ByteArray, ksn: ByteArray): DukptResult<DukptInput> {
       return when(keyType){
            DukptKeyType.BDK ->{
                dukptBdk = byteArrayToHexString(dukptKey)
                dukptksn = byteArrayToHexString(ksn)
                dukptKeyType = DukptKeyType.BDK
                generateIPEK(ksn, dukptKey)
                val dukptInput = DukptInput(
                    dukptBdk = dukptBdk,
                    dukptIpek = dukptIpek,
                    dukptKsn = dukptksn,
                    dataKey = dukptDataKey,
                    dukptKeyType = dukptKeyType
                )
                DukptResult.Success(dukptInput)
            }
            DukptKeyType.IPEK -> {
                dukptIpek = byteArrayToHexString(dukptKey)
                dukptksn = byteArrayToHexString(ksn)

                val dataKey = getDatekey(ksn,dukptKey)
                dukptDataKey = byteArrayToHexString(dataKey).take(32)

                dukptKeyType = DukptKeyType.IPEK
                val dukptInput = DukptInput(
                    dukptIpek = dukptIpek,
                    dukptKsn = dukptksn,
                    dataKey = dukptDataKey,
                    dukptKeyType = dukptKeyType
                )
                DukptResult.Success(dukptInput)
            }
            DukptKeyType.UNKNOWN -> DukptResult.Error(DukptError.UNKNOWN_KEY_TYPE.error)
            null -> TODO()
        }
    }

    private fun nothing(): Nothing {
        TODO()
    }

    @Throws(Exception::class)
     fun tdesEnc(data: ByteArray, key: ByteArray): ByteArray {
        val cipher: Cipher = if (key.size == 8) {
            Cipher.getInstance("DES").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "DES"))
            }
        } else {
            Cipher.getInstance("DESede").apply {
                init(Cipher.ENCRYPT_MODE, SecretKeySpec(concat(key, 0, 16, key, 0, 8), "DESede"))
            }
        }

        return cipher.doFinal(data)
    }

    @Throws(Exception::class)
     fun generateIPEK(ksn: ByteArray, bdkbytes: ByteArray): ByteArray {


        var temp = trim(ksn, 8)
        var keyTemp = bdkbytes.copyOf()

        temp[7] = (temp[7].toInt() and 0xE0).toByte()
        var temp2 = tdesEnc(temp, keyTemp)
        var result = trim(temp2, 8)

        keyTemp[0] = (keyTemp[0].toInt() xor 0xC0).toByte()
        keyTemp[1] = (keyTemp[1].toInt() xor 0xC0).toByte()
        keyTemp[2] = (keyTemp[2].toInt() xor 0xC0).toByte()
        keyTemp[3] = (keyTemp[3].toInt() xor 0xC0).toByte()
        keyTemp[8] = (keyTemp[8].toInt() xor 0xC0).toByte()
        keyTemp[9] = (keyTemp[9].toInt() xor 0xC0).toByte()
        keyTemp[10] = (keyTemp[10].toInt() xor 0xC0).toByte()
        keyTemp[11] = (keyTemp[11].toInt() xor 0xC0).toByte()

        temp2 = tdesEnc(temp, keyTemp)
        result = concat(result, trim(temp2, 8))
        dukptIpek = byteArrayToHexString(result)
        Log.e("DUKPT","IPEK = $dukptIpek")
        val dataKey = getDatekey(ksn,result)
        dukptDataKey = byteArrayToHexString(dataKey).take(32)
        Log.e("DUKPT","Data key = $dukptDataKey")
        return result
    }

    @Throws(java.lang.Exception::class)
    private fun getDatekey(ksn: ByteArray, ipek: ByteArray): ByteArray {
        var key: ByteArray = trim(ipek, 16)
        val cnt = ByteArray(3)
        cnt[0] = (ksn[7].toInt() and 0x1F).toByte()
        cnt[1] = ksn[8]
        cnt[2] = ksn[9]
        val temp = ByteArray(8)
        System.arraycopy(ksn, 2, temp, 0, 6)
        temp[5] = (temp[5].toInt() and 0xE0).toByte()
        var shift = 0x10
        while (shift > 0) {
            if ((cnt[0].toInt() and shift) > 0) {
                temp[5] = (temp[5].toInt() or shift).toByte()
                key = NRKGP(key, temp)
            }
            shift = shift shr 1
        }

        shift = 0x80
        while (shift > 0) {
            if ((cnt[1].toInt() and shift) > 0) {
                temp[6] = (temp[6].toInt() or shift).toByte()
                key = NRKGP(key, temp)
            }
            shift = shift shr 1
        }

        shift = 0x80
        while (shift > 0) {
            if ((cnt[2].toInt() and shift) > 0) {
                temp[7] = (temp[7].toInt() or shift).toByte()
                key = NRKGP(key, temp)
            }
            shift = shift shr 1
        }


        key[5] = (key[5].toInt() xor 0xFF).toByte()
        key[13] = (key[13].toInt() xor 0xFF).toByte()

        key = tdesEnc(key, key)
        return key
    }

    @Throws(java.lang.Exception::class)
    private fun NRKGP(key: ByteArray, ksn: ByteArray): ByteArray {
        val key_temp: ByteArray = trim(key, 8)
        var temp = ByteArray(8)
        for (i in 0..7) {
            temp[i] = (ksn[i].toInt() xor key[8 + i].toInt()).toByte()
        }
        var res = tdesEnc(temp, key_temp)
        val key_r = res
        for (i in 0..7) {
            key_r[i] = (key_r[i].toInt() xor key[8 + i].toInt()).toByte()
        }
        key_temp[0] = (key_temp[0].toInt() xor 0xC0).toByte()
        key_temp[1] = (key_temp[1].toInt() xor 0xC0).toByte()
        key_temp[2] = (key_temp[2].toInt() xor 0xC0).toByte()
        key_temp[3] = (key_temp[3].toInt() xor 0xC0).toByte()
        key[8] = (key[8].toInt() xor 0xC0).toByte()
        key[9] = (key[9].toInt() xor 0xC0).toByte()
        key[10] = (key[10].toInt() xor 0xC0).toByte()
        key[11] = (key[11].toInt() xor 0xC0).toByte()

        temp = ByteArray(8)
        for (i in 0..7) {
            temp[i] = (ksn[i].toInt() xor key[8 + i].toInt()).toByte()
        }

        res = tdesEnc(temp, key_temp)
        val key_l = res
        for (i in 0..7) {
            key[i] = (key_l[i].toInt() xor key[8 + i].toInt()).toByte()
        }
        System.arraycopy(key_r, 0, key, 8, 8)
        return key
    }


}

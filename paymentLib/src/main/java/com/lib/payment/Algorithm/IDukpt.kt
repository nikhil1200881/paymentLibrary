package com.lib.payment.Algorithm

import Enum.DukptKeyType
import Enum.DukptVersion

interface IDukpt {

    fun initializeDukpt(
        dukptVersion: DukptVersion = DukptVersion.UNKNOWN,
        keyType: DukptKeyType = DukptKeyType.BDK,
        key: ByteArray,
        ksn: ByteArray
    ): DukptResult<DukptInput>

    fun getIpek(): String

    fun getDataKey(): String

    fun encryptData(plainData: ByteArray): String

    fun decryptData(encryptedData: ByteArray): String

}
package com.lib.payment.Algorithm

import Enum.DukptVersion
import Enum.KeyType

interface IDukptAes {

    fun initializeDukptAes(
        ksn: ByteArray,
        bdk: ByteArray,
        keyType: KeyType,
        dukptVersion: DukptVersion,
        workingKeyType: KeyType
    ): DukptResult<DukptAesOutput>
}
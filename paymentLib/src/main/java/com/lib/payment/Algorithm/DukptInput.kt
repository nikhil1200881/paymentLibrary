package com.lib.payment.Algorithm

import Enum.DukptKeyType
import Enum.DukptVersion

data class DukptInput(
    val dukptBdk: String? = "",
    val dukptIpek: String? = "",
    val dukptKsn: String? = "",
    val dataKey: String? = "",
    val dukptKeyType: DukptKeyType? = DukptKeyType.UNKNOWN
)

data class DukptAesOutput(
    val dukptAes_initalKey: String? = "",
    val dukptAes_bdk: String? = "",
    val ksnCounter: String? = "",
    val ksn: String? = "",
    val keyEncryptionKey: String? ="",
    val pinEncryptionKey: String? = "",
    val macGenerationKey: String? = "",
    val macVerificationKey: String? = "",
    val macBothWaysKey: String? = "",
    val dataEncryptKey: String? = "",
    val dataDecryptKey: String? = "",
    val dataBothWaysKey: String? = ""
)



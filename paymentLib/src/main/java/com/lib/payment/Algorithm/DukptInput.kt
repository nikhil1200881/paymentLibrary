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



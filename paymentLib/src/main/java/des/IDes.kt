package des

import com.lib.payment.Algorithm.Constant

interface IDes {

    fun encrypt(
        data: String? = Constant.EMPTY_STRING,
        key: String? = Constant.EMPTY_STRING,
        paddingMode: PaddingMode? = PaddingMode.UNKNOWN,
        encryptionMode: Mode? = Mode.UNKNOWN,
        initialVector: String? = Constant.EMPTY_STRING
    ): DesResult<DesOutput>


    fun decrypt(
        data: String? = Constant.EMPTY_STRING,
        key: String? = Constant.EMPTY_STRING,
        paddingMode: PaddingMode? = PaddingMode.UNKNOWN,
        decryptionMode: Mode? = Mode.UNKNOWN,
        initialVector: String? = Constant.EMPTY_STRING
    ): DesResult<DesOutput>
}
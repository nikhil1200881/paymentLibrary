package des

enum class PaddingMode(val paddingMode: Int, val paddingName: String) {
    NONE(0,"NoPadding"),
    ZEROS(1,"ZeroBytePadding"),
    SPACES(2,"SpacePadding"),
    ANSI_X9_23(3,"X9.23Padding"),
    ISO_10126(4,"ISO10126Padding"),
    PKCS_5(5,"PKCS5Padding"),
    PKCS_7(6,"PKCS7Padding"),
    ISO_7816_4(7,"ISO7816-4Padding"),
    RIJNDAEL(8,"RijndaelPadding"),
    ISO9797_1_PADDING_METHOD_1(9,"ISO9797Method1"),
    ISO9797_1_PADDING_METHOD_2(10,"ISO9797Method2"),
    UNKNOWN(-1,"UnknownPadding")
}
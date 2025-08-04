package des

enum class DesError(desError: Int, errorMessage: String) {
    INVALID_KEY_LENGTH(0, "Invalid Key Length"),
    INVALID_DATA(1, "Data that Needs to encrypt is Empty or null"),
    UNKNOWN_DES_TYPE(-1, "Unknown DES type"),
    INVALID_PADDING_MODE(2, "Invalid Padding Mode"),
    INVALID_ENCRYPTION_MODE(3, "Invalid Encryption Mode"),
    UNSUPPORTED_ENCRYPTION_MODE(4, "Unsupported Encryption Mode"),

}
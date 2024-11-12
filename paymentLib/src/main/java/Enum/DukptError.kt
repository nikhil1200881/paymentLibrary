package Enum

enum class DukptError(val error: Int) {
    UNKNOWN_KEY_TYPE(-1),
    INVALID_KSN_LENGTH(-2),
    INVALID_KEY_LENGTH(-3),
    EMPTY_KEY(-4),
    EMPTY_KSN(-5),
    UNKNOWN(-1001)
}
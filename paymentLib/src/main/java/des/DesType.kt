package des

enum class DesType(val desType: Int, val desName: String) {
    DES(0,"DES"),
    TDES(1,"DESede"),
    UNKNOWN(-1, "Unknown")
}
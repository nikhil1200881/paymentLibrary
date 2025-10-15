package Enum

enum class CryptoType(val cryptoType: Int, val cryptoName: String) {
    Encryption(0, "Encryption"),
    Decryption(1, "Decryption"),
    UNKNOWN(-1, "Unknown")

}
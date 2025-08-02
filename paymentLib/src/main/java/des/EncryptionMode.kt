package des

enum class EncryptionMode(val encryptionMode: Int, val encryptionModeName: String){
    ECB(0,"ECB"),
    CBC(1,"CBC"),
    CFB_8(2,"CFB8"),
    CFB_64(3,"CFB"),
    OFB_8(4,"OFB8"),
    OFB_64(5,"OFB"),
    UNKNOWN(-1,"Unknown")

}
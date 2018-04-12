package io.ktor.network.tls


enum class SecretExchangeType {
    RSA,
    DHE,
    ECDHE
}

class CipherSuite(
    val code: Short,
    val name: String,
    val openSSLName: String,
    val exchangeType: SecretExchangeType,
    val jdkCipherName: String,
    val keyStrength: Int,
    val fixedIvLength: Int,
    val ivLength: Int,
    val cipherTagSizeInBytes: Int,
    val macName: String,
    val macStrength: Int,
    val hashName: String
) {
    val keyStrengthInBytes = keyStrength / 8
    val macStrengthInBytes = macStrength / 8
}

object SupportedCiphers {
    internal val TLS_RSA_WITH_AES_128_GCM_SHA256 = CipherSuite(
        0x009c,
        "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES128-GCM-SHA256",
        SecretExchangeType.RSA, "AES/GCM/NoPadding",
        128, 4, 12, 16,
        "HmacSHA256", 0, "SHA-256"
    )

//    internal val ECDHE_ECDSA_AES256_SHA384 = CipherSuite(
//        0xc02c.toShort(),
//        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384",
//        SecretExchangeType.ECDHE, "AES/GCM/NoPadding",
//        256, TODO(), TODO(), TODO(), "", 0, "SHA-384"
//    )

    internal val SUITES: Map<Short, CipherSuite> = listOf(
        TLS_RSA_WITH_AES_128_GCM_SHA256
    ).map { it.code to it }.toMap()
}


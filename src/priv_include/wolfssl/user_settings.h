#ifndef _USER_SETTINGS_H_
#define _USER_SETTINGS_H_

#ifdef __cplusplus
extern "C" {
#endif


/* Feature support */
#define WOLFSSL_TLS13
#define WOLFSSL_USER_IO
#define WOLF_CRYPTO_CB
#define WOLF_CRYPTO_DEV
#define WOLFSSL_KEY_GEN
#define WOLFSSL_ALWAYS_VERIFY_CB
#define HAVE_CRL_IO
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_NULL_CIPHER
#define HAVE_SECRET_CALLBACK
#define HAVE_WOLF_BIGINT
#define HAVE_PKCS11
#define WOLFSSL_DUAL_ALG_CERTS
#define WOLFSSL_ASN_TEMPLATE
#define LARGE_STATIC_BUFFERS

#define NO_PWDBASED
#define NO_WRITEV
#define NO_DEV_URANDOM
#define NO_MULTIBYTE_PRINT
#define NO_OLD_TLS
#define WOLFSSL_NO_TLS12
#define NO_OLD_RNGNAME
#define WOLFSSL_NO_SOCK
#define NO_PKCS11_ECDH
#define NO_PKCS11_EC_KEYGEN


/* Enable experimental features */
#define WOLFSSL_EXPERIMENTAL_SETTINGS


/* Algorithm support and configuration */
#define HAVE_ECC
#define HAVE_ECC384
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define WC_RSA_PSS
#define WC_RSA_BLINDING
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_HKDF
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_HAVE_KYBER
#define WOLFSSL_WC_KYBER
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define HAVE_LIBOQS

// #define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
// #define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#define WC_DILITHIUM_CACHE_MATRIX_A
#define WC_DILITHIUM_CACHE_PRIV_VECTORS
#define WC_DILITHIUM_CACHE_PUB_VECTORS
// #define WOLFSSL_DILITHIUM_SMALL
// #define WOLFSSL_SMALL_STACK

#define WOLFSSL_KEEP_DECODED_PRIVATE_KEY

#define NO_SHA
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_AES_192
#define WOLFSSL_NO_SPHINCS


/* Debugging */
#define DEBUG_WOLFSSL
#define WOLFSSL_MAX_ERROR_SZ 224
// #define WOLFSSL_DEBUG_PKCS11


/* Math configuration */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_SP_4096
#define WOLFSSL_SP_384
#define WOLFSSL_SP_521
#define WOLFSSL_SP_ASM

#if defined(__x86_64__)

#define WOLFSSL_SP_X86_64
#define WOLFSSL_SP_X86_64_ASM

#elif defined(__aarch64__)

#define WOLFSSL_SP_ARM64
#define WOLFSSL_SP_ARM64_ASM

#endif

#ifdef __cplusplus
}
#endif

#endif /* _USER_SETTINGS_H_ */

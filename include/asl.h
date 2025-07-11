#ifndef AGILE_SECURITY_LIBRARY_H
#define AGILE_SECURITY_LIBRARY_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "asl_config.h"

#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7
#define PKCS11_LABEL_TERMINATOR "\r\n"

/* Properly set the API visibility */
#if defined(BUILDING_KRITIS3M_ASL)
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || defined(_WIN32_WCE)
#if defined(BUILDING_KRITIS3M_ASL_SHARED)
#define KRITIS3M_ASL_API __declspec(dllexport)
#else
#define KRITIS3M_ASL_API
#endif
#else
#define KRITIS3M_ASL_API
#endif
#else /* BUILDING_KRITIS3M_ASL */
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || defined(_WIN32_WCE)
#if defined(BUILDING_KRITIS3M_ASL_SHARED)
#define KRITIS3M_ASL_API __declspec(dllimport)
#else
#define KRITIS3M_ASL_API
#endif
#else
#define KRITIS3M_ASL_API
#endif
#endif /* BUILDING_KRITIS3M_ASL */

/* Error types of the library */
enum ASL_ERROR_CODES
{
        ASL_SUCCESS = 0,
        ASL_MEMORY_ERROR = -1,
        ASL_ARGUMENT_ERROR = -2,
        ASL_INTERNAL_ERROR = -3,
        ASL_CERTIFICATE_ERROR = -4,
        ASL_PKCS11_ERROR = -5,
        ASL_CONN_CLOSED = -6,
        ASL_WANT_READ = -7,
        ASL_WANT_WRITE = -8,
        ASL_PSK_ERROR = -9,
        ASL_NO_PEER_CERTIFICATE = -10,
};

/* Available Log levels. Default is ERR. */
enum ASL_LOG_LEVEL
{
        ASL_LOG_LEVEL_ERR = 1U,
        ASL_LOG_LEVEL_WRN = 2U,
        ASL_LOG_LEVEL_INF = 3U,
        ASL_LOG_LEVEL_DBG = 4U,
};

/* Function pointer type for logging callbacks. */
typedef void (*asl_log_callback_t)(int32_t level, char const* message);

/* Function pointer type for client psk. This callback is executed once during
 * connection establishment for each session. The user has to copy the PSK in
 * base64 encoding into the `key` buffer and an ASCII based identity string into
 * the `identity` buffer. Both buffers are 64 bytes in size. The `ctx` parameter
 * is a user provided pointer provided during initialization.
 * The provided key is base64 decoded and used as the external PSK for the PSK
 * ImporterInterface. The provided identity is used as the context value within the
 * ImportedIdentity structure of the ImporterInterface. The actual identity within
 * that structure to be sent to the server is the identity provided during initialization.
 * The return value must be the length of the base64 encoded key excluding the
 * null-terminator. In case of an error, a negative number should be returned (the
 * actual negative value is ignored).
 */
typedef unsigned int (*asl_psk_client_callback_t)(char* key, char* identity, void* ctx);

/* Function pointer type for server psk. This callback is executed once during
 * connection establishment for each session. The `identity` parameter points to a
 * char array containing the context value of the received ImportedIdentity structure
 * of the PSK ImporterInterface. As this buffer is a stack-allocated copy, it can safely
 * be modified by the user within its 64 byte bounds. The user has to provide a base64
 * encoded key into the `key` buffer (which is also 64 bytes in size). This key is base64
 * decoded and then used as the external PSK for the PSK ImporterInterface. The `ctx`
 * parameter is a user provided pointer provided during initialization.
 * The return value must be the length of the base64 encoded key excluding the
 * null-terminator. In case of an error, a negative number should be returned (the
 * actual negative value is ignored).
 */
typedef unsigned int (*asl_psk_server_callback_t)(char* key, char* identity, void* ctx);

/* Data structure for the library configuration. */
typedef struct
{
        bool logging_enabled;
        int32_t log_level;
        asl_log_callback_t log_callback;
} asl_configuration;

/* Enum for the different key exchange (KEX) methods
 * to be used during the handshake. */
enum asl_key_exchange_method
{
        ASL_KEX_DEFAULT = 0,
        ASL_KEX_CLASSIC_SECP256,
        ASL_KEX_CLASSIC_SECP384,
        ASL_KEX_CLASSIC_SECP521,
        ASL_KEX_CLASSIC_X25519,
        ASL_KEX_CLASSIC_X448,
        ASL_KEX_PQC_MLKEM512,
        ASL_KEX_PQC_MLKEM768,
        ASL_KEX_PQC_MLKEM1024,
        ASL_KEX_HYBRID_SECP256_MLKEM512,
        ASL_KEX_HYBRID_SECP384_MLKEM768,
        ASL_KEX_HYBRID_SECP256_MLKEM768,
        ASL_KEX_HYBRID_SECP521_MLKEM1024,
        ASL_KEX_HYBRID_SECP384_MLKEM1024,
        ASL_KEX_HYBRID_X25519_MLKEM512,
        ASL_KEX_HYBRID_X448_MLKEM768,
        ASL_KEX_HYBRID_X25519_MLKEM768,
};

/* Data structure for the endpoint configuration */
typedef struct
{
        bool mutual_authentication;
        enum asl_key_exchange_method key_exchange_method;
        char const* ciphersuites;
        char const* server_name;

        struct
        {
                char const* module_path;
                char const* module_pin;
                int slot_id;
                bool use_for_all;

        } pkcs11;

        struct
        {
                bool enable_psk;
                bool enable_kex;
                bool enable_cert_auth;
                bool use_external_callbacks;
                bool pre_extracted;

                char const* key;
                char const* identity;

                void* callback_ctx;
                asl_psk_client_callback_t client_cb;
                asl_psk_server_callback_t server_cb;

        } psk;

        struct
        {
                uint8_t const* buffer;
                size_t size;

        } device_certificate_chain;

        struct
        {
                uint8_t const* buffer;
                size_t size;

                /* Additional key in case of hybrid signatures */
                uint8_t const* additional_key_buffer;
                size_t additional_key_size;

        } private_key;

        struct
        {
                uint8_t const* buffer;
                size_t size;

        } root_certificate;

        char const* keylog_file;

} asl_endpoint_configuration;

/* Data structure for an endpoint (definition is hidden in source file) */
typedef struct asl_endpoint asl_endpoint;

/* Data structure for an active session (definition is hidden in source file) */
typedef struct asl_session asl_session;

/* Data structure for handshake metics */
typedef struct
{
        uint32_t duration_us;
        uint32_t tx_bytes;
        uint32_t rx_bytes;
} asl_handshake_metrics;

/* Create the default config for the Agile Security Library (asl). */
KRITIS3M_ASL_API asl_configuration asl_default_config(void);

/* Create the default config for an asl endpoint. */
KRITIS3M_ASL_API asl_endpoint_configuration asl_default_endpoint_config(void);

/* Initialize the Agile Security Library (asl).
 *
 * Parameter is a pointer to a filled asl_configuration structure.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error
 * (error message is logged to the console).
 */
KRITIS3M_ASL_API int asl_init(asl_configuration const* config);

/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
KRITIS3M_ASL_API asl_endpoint* asl_setup_server_endpoint(asl_endpoint_configuration const* config);

/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
KRITIS3M_ASL_API asl_endpoint* asl_setup_client_endpoint(asl_endpoint_configuration const* config);

/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
KRITIS3M_ASL_API asl_session* asl_create_session(asl_endpoint* endpoint, int socket_fd);

/* Perform the TLS handshake for a newly created session.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged to
 * the console). In case the handshake is not done yet and you have to call the method again
 * when new data from the peer is present, ASL_WANT_READ is returned.
 */
KRITIS3M_ASL_API int asl_handshake(asl_session* session);

/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, negative error code on failure
 * (error message is logged to the console). In case we have not received enough data
 * to decode the TLS record, ASL_WANT_READ is returned. In that case, you have to call
 * the method again when new data from the peer is present.
 */
KRITIS3M_ASL_API int asl_receive(asl_session* session, uint8_t* buffer, int max_size);

/* Send data to the TLS remote peer.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console). In case we cannot write the data in one call, ASL_WANT_WRITE is returned,
 * indicating that you have to call the method again (with the same data!) once the socket is
 * writable again.
 */
KRITIS3M_ASL_API int asl_send(asl_session* session, uint8_t const* buffer, int size);

/* Get the peer certificate (in DER encoding).
 *
 * The peer certificate is copied into the provided buffer. The buffer must be large enough
 * to hold the certificate (on entry, *size must contain the buffer size). The size in bytes
 * of the certificate is stored in *size.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console).
 */
KRITIS3M_ASL_API int asl_get_peer_certificate(asl_session* session, uint8_t* buffer, size_t* size);

/* Get metics of the handshake. */
KRITIS3M_ASL_API asl_handshake_metrics asl_get_handshake_metrics(asl_session* session);

/* Close the connection of the active session */
KRITIS3M_ASL_API void asl_close_session(asl_session* session);

/* Free ressources of a session. */
KRITIS3M_ASL_API void asl_free_session(asl_session* session);

/* Free ressources of an endpoint. */
KRITIS3M_ASL_API void asl_free_endpoint(asl_endpoint* endpoint);

/* Print human-readable error message */
KRITIS3M_ASL_API char const* asl_error_message(int error_code);

/* Access to the internal WolfSSL API */
#if defined(KRITIS3M_ASL_INTERNAL_API)

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

/* Get the internal WolfSSL CTX object */
KRITIS3M_ASL_API WOLFSSL_CTX* asl_get_wolfssl_context(asl_endpoint* endpoint);

/* Get the internal WolfSSL session object */
KRITIS3M_ASL_API WOLFSSL* asl_get_wolfssl_session(asl_session* session);

#endif

/* Cleanup any library resources */
KRITIS3M_ASL_API void asl_cleanup(void);

#endif /* AGILE_SECURITY_LIBRARY_H */

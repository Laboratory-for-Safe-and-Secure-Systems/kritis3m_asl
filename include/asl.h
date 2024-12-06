#ifndef AGILE_SECURITY_LIBRARY_H
#define AGILE_SECURITY_LIBRARY_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#include "asl_config.h"

#define PKCS11_LABEL_IDENTIFIER "pkcs11:"
#define PKCS11_LABEL_IDENTIFIER_LEN 7

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
};

/* Available Log levels. Default is ERR. */
enum ASL_LOG_LEVEL
{
        ASL_LOG_LEVEL_ERR = 1U,
        ASL_LOG_LEVEL_WRN = 2U,
        ASL_LOG_LEVEL_INF = 3U,
        ASL_LOG_LEVEL_DBG = 4U,
};

/* Function pointer type fo logging callbacks. */
typedef void (*asl_log_callback_t)(int32_t level, char const* message);

/* Data structure for the library configuration */
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

/* Enum for the different modes during the handshake
 * regarding hybrid signatures. */
enum asl_hybrid_signature_mode
{
        ASL_HYBRID_SIGNATURE_MODE_DEFAULT = 0,
        ASL_HYBRID_SIGNATURE_MODE_NATIVE,
        ASL_HYBRID_SIGNATURE_MODE_ALTERNATIVE,
        ASL_HYBRID_SIGNATURE_MODE_BOTH,
};

/* Data structure for the endpoint configuration */
typedef struct
{
        bool mutual_authentication;
        bool no_encryption;
        enum asl_hybrid_signature_mode hybrid_signature_mode;
        enum asl_key_exchange_method key_exchange_method;

        struct
        {
                struct
                {
                        char const* path;
                        char const* pin;
                } long_term_crypto_module;

                struct
                {
                        char const* path;
                } ephemeral_crypto_module;
        } pkcs11;

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

/* Enable/disable logging infrastructure.
 *
 * Parameter is a boolean value to enable or disable logging.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
KRITIS3M_ASL_API int asl_enable_logging(bool enable);

/* Set a custom logging callback.
 *
 * Parameter is a function pointer to the logging callback.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
KRITIS3M_ASL_API int asl_set_log_callback(asl_log_callback_t new_callback);

/* Update the log level.
 *
 * Parameter is the new log level.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
KRITIS3M_ASL_API int asl_set_log_level(int32_t new_log_level);

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

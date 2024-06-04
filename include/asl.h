#ifndef AGILE_SECURITY_LIBRARY_H
#define AGILE_SECURITY_LIBRARY_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>


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
    ASL_LOG_LEVEL_ERR   = 1U,
    ASL_LOG_LEVEL_WRN   = 2U,
    ASL_LOG_LEVEL_INF   = 3U,
    ASL_LOG_LEVEL_DBG   = 4U,
};


/* Function pointer type for custom logging callbacks. */
typedef void (*asl_custom_log_callback)(int32_t level, char const* message);


/* Data structure for the library configuration */
typedef struct
{
        bool loggingEnabled;
        int32_t logLevel;
        asl_custom_log_callback customLogCallback;

        bool secure_element_support;
        char const* secure_element_middleware_path;
}
asl_configuration;


/* Enum for the different modes during the handshake
 * regarding hybrid signatures. */
enum asl_hybrid_signature_mode
{
        HYBRID_SIGNATURE_MODE_NATIVE = 1,
        HYBRID_SIGNATURE_MODE_ALTERNATIVE = 2,
        HYBRID_SIGNATURE_MODE_BOTH = 3
};


/* Data structure for the endpoint configuration */
typedef struct
{
        bool mutual_authentication;
        bool no_encryption;
        bool use_secure_element;
        bool secure_element_import_keys;

        enum asl_hybrid_signature_mode hybrid_signature_mode;

        struct
        {
                uint8_t const* buffer;
                size_t size;
        }
        device_certificate_chain;

        struct
        {
                uint8_t const* buffer;
                size_t size;

                /* Additional key in case of hybrid signatures */
                uint8_t const* additional_key_buffer;
                size_t additional_key_size;
        }
        private_key;

        struct
        {
                uint8_t const* buffer;
                size_t size;
        }
        root_certificate;

        char const* keylog_file;
}
asl_endpoint_configuration;


/* Data structure for an endpoint (definition is hidden in source file) */
typedef struct asl_endpoint asl_endpoint;


/* Data structure for an active session (definition is hidden in source file) */
typedef struct asl_session asl_session;


/* Data structure for handshake metics */
typedef struct
{
        uint32_t duration_us;
        uint32_t txBytes;
        uint32_t rxBytes;
}
asl_handshake_metrics;


/* Initialize the Agile Security Library (asl).
 *
 * Parameter is a pointer to a filled asl_configuration structure.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error
 * (error message is logged to the console).
 */
int asl_init(asl_configuration const* config);


/* Enable/disable logging infrastructure.
 *
 * Parameter is a boolean value to enable or disable logging.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_enable_logging(bool enable);


/* Set a custom logging callback.
 *
 * Parameter is a function pointer to the custom logging callback.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_set_custom_log_callback(asl_custom_log_callback new_callback);


/* Update the log level.
 *
 * Parameter is the new log level.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_set_log_level(int32_t new_log_level);


/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
asl_endpoint* asl_setup_server_endpoint(asl_endpoint_configuration const* config);


/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
asl_endpoint* asl_setup_client_endpoint(asl_endpoint_configuration const* config);


/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
asl_session* asl_create_session(asl_endpoint* endpoint, int socket_fd);


/* Perform the TLS handshake for a newly created session.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged to
 * the console). In case the handshake is not done yet and you have to call the method again
 * when new data from the peer is present, ASL_WANT_READ is returned.
 */
int asl_handshake(asl_session* session);


/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, negative error code on failure
 * (error message is logged to the console). In case we have not received enough data
 * to decode the TLS record, ASL_WANT_READ is returned. In that case, you have to call
 * the method again when new data from the peer is present.
 */
int asl_receive(asl_session* session, uint8_t* buffer, int max_size);


/* Send data to the TLS remote peer.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console). In case we cannot write the data in one call, ASL_WANT_WRITE is returned,
 * indicating that you have to call the method again (with the same data!) once the socket is
 * writable again.
 */
int asl_send(asl_session* session, uint8_t const* buffer, int size);


/* Get metics of the handshake. */
asl_handshake_metrics asl_get_handshake_metrics(asl_session* session);


/* Close the connection of the active session */
void asl_close_session(asl_session* session);


/* Free ressources of a session. */
void asl_free_session(asl_session* session);


/* Free ressources of an endpoint. */
void asl_free_endpoint(asl_endpoint* endpoint);


/* Print human-readable error message */
char const* asl_error_message(int error_code);



/* Access to the internal WolfSSL API */
#if defined(KRITIS3M_ASL_INTERNAL_API)

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"

/* Get the internal WolfSSL CTX object */
WOLFSSL_CTX* asl_get_wolfssl_contex(asl_endpoint* endpoint);

/* Get the internal WolfSSL session object */
WOLFSSL* asl_get_wolfssl_session(asl_session* session);

#endif


#endif /* AGILE_SECURITY_LIBRARY_H */

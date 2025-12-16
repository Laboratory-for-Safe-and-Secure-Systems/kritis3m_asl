#ifndef ASL_TYPES_H
#define ASL_TYPES_H

#include <errno.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "asl.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

enum connection_state
{
        CONNECTION_STATE_NOT_CONNECTED,
        CONNECTION_STATE_HANDSHAKE,
        CONNECTION_STATE_CONNECTED,
};

/* Data structure for an endpoint */
struct asl_endpoint
{
        WOLFSSL_CTX* wolfssl_context;
        char* ciphersuites;

        struct
        {
#ifdef HAVE_PKCS11
                Pkcs11Dev device;
                Pkcs11Token token;
#endif
                char const* pin;
                int device_id;
                bool initialized;

        } pkcs11_module;

#ifndef NO_PSK
        struct
        {
                bool use_external_callbacks;
                bool enable_cert_auth;
                bool pre_extracted;

                char* identity;
                void* key; /* either a byte array containing the key or
                            * or the callback_ctx in case those are used */
                size_t key_len;

                asl_psk_client_callback_t client_cb;
                asl_psk_server_callback_t server_cb;

        } psk;
#endif

#if defined(HAVE_SECRET_CALLBACK)
        char* keylog_file;
#endif
};

/* Data structure for an active session */
struct asl_session
{
        WOLFSSL* wolfssl_session;
        enum connection_state state;
        asl_endpoint* endpoint;

        struct
        {
                struct timespec start_time;
                struct timespec end_time;
                uint32_t tx_bytes;
                uint32_t rx_bytes;

        } handshake_metrics;

#ifndef NO_PSK
        struct
        {
                char* identity;
                uint8_t* key;
                size_t key_len;

        } external_psk;

#endif
};

/* PKCS#11 Device ID handling. Each endpoint needs a unique DevID for
 * its long-term crypto module (secure element). All sessions for a
 * given endpoint inherit that module with its DevID.
 * Furthermore, each session requires another unique DevID for its
 * ephemeral crypto module.
 *
 * We implement that by using two static counters that count up modulo
 * a fixed number. */
#define DEVICE_ID_OFFSET_ENDPOINT 1
#define DEVICE_ID_MAX_ENDPOINT 1000
#define DEVICE_ID_OFFSET_SESSION DEVICE_ID_MAX_ENDPOINT
#define DEVICE_ID_MAX_SESSION 10000

#if defined(KRITIS3M_ASL_HEAP_TRACKING) && defined(WOLFSSL_TRACK_MEMORY)

#define TRACK_WOLFSS_HEAP_USAGE_START()                                                            \
        {                                                                                          \
                long peak = wolfCrypt_heap_peakBytes_checkpoint();                                 \
                long curr = wolfCrypt_heap_peakBytes_checkpoint();                                 \
                (void) peak;                                                                       \
                asl_log(ASL_LOG_LEVEL_INF, "%s (start): heap=%ld", __func__, curr);                \
        }

#define TRACK_WOLFSS_HEAP_USAGE_END()                                                              \
        {                                                                                          \
                long peak = wolfCrypt_heap_peakBytes_checkpoint();                                 \
                long curr = wolfCrypt_heap_peakBytes_checkpoint();                                 \
                asl_log(ASL_LOG_LEVEL_INF, "%s (end): heap=%ld, peak=%ld", __func__, curr, peak);  \
        }

#elif defined(KRITIS3M_ASL_HEAP_TRACKING) && !defined(WOLFSSL_TRACK_MEMORY)

#warning "Heap tracking is enabled, but WOLFSSL_TRACK_MEMORY is not defined. No heap tracking will be done."
#warning "Please enable WOLFSSL_TRACK_MEMORY in the wolfSSL build configuration."

#else

#define TRACK_WOLFSS_HEAP_USAGE_START()
#define TRACK_WOLFSS_HEAP_USAGE_END()

#endif

#if defined(KRITIS3M_ASL_LOG_INIT_DURATION)

#define TRACK_INIT_DURATION_START()                                                                \
        struct timespec init_start_time;                                                           \
        take_timestamp(&init_start_time);

#define TRACK_INIT_DURATION_END()                                                                  \
        struct timespec init_end_time;                                                             \
        take_timestamp(&init_end_time);                                                            \
        double init_duration_us = (init_end_time.tv_sec - init_start_time.tv_sec) * 1000000.0 +    \
                                  (init_end_time.tv_nsec - init_start_time.tv_nsec) / 1000.0;      \
        asl_log(ASL_LOG_LEVEL_INF,                                                                 \
                "TLS endpoint initialization duration: %.2f us",                                   \
                (double) init_duration_us);

#else

#define TRACK_INIT_DURATION_START()
#define TRACK_INIT_DURATION_END()

#endif

/* Internal helper method to take a timestamp for timing measurements*/
int take_timestamp(struct timespec* ts);

#endif /* ASL_TYPES_H */

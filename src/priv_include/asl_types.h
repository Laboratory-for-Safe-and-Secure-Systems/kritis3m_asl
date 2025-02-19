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
                asl_psk_client_callback_t psk_client_cb;
                asl_psk_server_callback_t psk_server_cb;
                char* master_key;
                void* callback_ctx;
                bool use_external_callbacks;
#ifdef WOLFSSL_CERT_WITH_EXTERN_PSK
                bool enable_certWithExternPsk;
#endif
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

#endif

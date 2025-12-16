
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "asl.h"
#include "asl_logging.h"
#include "asl_pkcs11.h"
#include "asl_psk.h"
#include "asl_types.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

#define ERROR_OUT(error_code, ...)                                                                 \
        {                                                                                          \
                asl_log(ASL_LOG_LEVEL_ERR, __VA_ARGS__);                                           \
                ret = error_code;                                                                  \
                goto cleanup;                                                                      \
        }

#if defined(KRITIS3M_ASL_CONSTANT_PRNG)

static uint32_t seed_counter = 0;

#endif

#if defined(_WIN32) && defined(_MSC_VER)

#include <winsock2.h>

int take_timestamp(struct timespec* ts)
{
        __int64 wintime;

        GetSystemTimeAsFileTime((FILETIME*) &wintime);

        wintime -= 116444736000000000i64;          // 1jan1601 to 1jan1970
        ts->tv_sec = wintime / 10000000i64;        // seconds
        ts->tv_nsec = wintime % 10000000i64 * 100; // nano-seconds

        return 0;
}

#else

int take_timestamp(struct timespec* ts)
{
        return clock_gettime(CLOCK_MONOTONIC, ts);
}

#endif

/* Create the default config for the Agile Security Library (asl). */
asl_configuration asl_default_config(void)
{
        asl_configuration default_config = {0};

        default_config.logging_enabled = true;
        default_config.log_level = ASL_LOG_LEVEL_WRN;
        default_config.log_callback = NULL;

        return default_config;
}

/* Create the default config for an asl endpoint. */
asl_endpoint_configuration asl_default_endpoint_config(void)
{
        asl_endpoint_configuration default_config = {0};

        default_config.mutual_authentication = true;
        default_config.key_exchange_method = ASL_KEX_DEFAULT;
        default_config.ciphersuites = NULL;
        default_config.server_name = NULL;

        default_config.pkcs11.module_path = NULL;
        default_config.pkcs11.module_pin = NULL;
        default_config.pkcs11.slot_id = -1;
        default_config.pkcs11.use_for_all = false;

        default_config.device_certificate_chain.buffer = NULL;
        default_config.device_certificate_chain.size = 0;

        default_config.private_key.buffer = NULL;
        default_config.private_key.size = 0;
        default_config.private_key.additional_key_buffer = NULL;
        default_config.private_key.additional_key_size = 0;

        default_config.root_certificate.buffer = NULL;
        default_config.root_certificate.size = 0;

        default_config.keylog_file = NULL;

        default_config.psk.enable_psk = false;
        default_config.psk.enable_kex = true;
        default_config.psk.use_external_callbacks = false;
        default_config.psk.enable_cert_auth = true;
        default_config.psk.pre_extracted = false;
        default_config.psk.key = NULL;
        default_config.psk.identity = NULL;
        default_config.psk.callback_ctx = NULL;
        default_config.psk.client_cb = NULL;
        default_config.psk.server_cb = NULL;

        return default_config;
}

/* Initialize the Agile Security Library (asl).
 *
 * Parameter is a pointer to a filled asl_configuration structure.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error
 * (error message is logged to the console).
 */
int asl_init(asl_configuration const* config)
{
        int ret = 0;

#if defined(KRITIS3M_ASL_CONSTANT_PRNG)
        /* Reset the seed counter for the constant PRNG*/
        seed_counter = 0;
#endif

        /* Configure the logging interface */
        ret = asl_prepare_logging(config);
        if (ret != ASL_SUCCESS)
                return ret;

        /* Initialize WolfSSL */
        ret = wolfSSL_Init();
        if (wolfssl_check_for_error(ret))
                return ASL_INTERNAL_ERROR;

        return ASL_SUCCESS;
}

/* Print human-readable error message */
char const* asl_error_message(int error_code)
{
        char const* errMsg = NULL;

        switch (error_code)
        {
        case ASL_SUCCESS:
                errMsg = "Success";
                break;
        case ASL_MEMORY_ERROR:
                errMsg = "Memory allocation error";
                break;
        case ASL_ARGUMENT_ERROR:
                errMsg = "Argument error";
                break;
        case ASL_INTERNAL_ERROR:
                errMsg = "Internal TLS lib error";
                break;
        case ASL_CERTIFICATE_ERROR:
                errMsg = "Certificate error";
                break;
        case ASL_PKCS11_ERROR:
                errMsg = "PKCS#11 error";
                break;
        case ASL_CONN_CLOSED:
                errMsg = "Connection closed";
                break;
        case ASL_WANT_READ:
                errMsg = "Need more data to read";
                break;
        case ASL_WANT_WRITE:
                errMsg = "Unable to write to the socket";
                break;
        case ASL_PSK_ERROR:
                errMsg = "PSK error";
                break;
        case ASL_NO_PEER_CERTIFICATE:
                errMsg = "No peer certificate available";
                break;
        default:
                errMsg = "Unknown error";
                break;
        }

        return errMsg;
}

/* Cleanup any library resources */
void asl_cleanup(void)
{
        /* Cleanup WolfSSL */
        wolfSSL_Cleanup();

        /* Nothing more to do at the moment... */
}

#if defined(KRITIS3M_ASL_CONSTANT_PRNG)

/* A constant seed for the PRNG for testing purposes (!!! INSECURE !!!) */

int rand_gen_seed(unsigned char* output, int sz)
{
        /* Increment the static seed counter */
        seed_counter++;

        uint32_t rem = sz;

        while (rem >= sizeof(uint32_t))
        {
                uint32_t counter_value = seed_counter;
                memcpy(output + (sz - rem), &counter_value, sizeof(uint32_t));
                rem -= sizeof(uint32_t);
                seed_counter++;
        }

        if (rem > 0)
        {
                uint32_t counter_value = seed_counter;
                memcpy(output + (sz - rem), &counter_value, rem);
        }

        return 0;
}
#endif

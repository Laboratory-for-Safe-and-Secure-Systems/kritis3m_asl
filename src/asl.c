
#include <stdlib.h>
#include <errno.h>

#if defined(_WIN32)

#include <winsock2.h>

#else

#include <sys/socket.h>

#endif

#include "asl.h"
#include "asl_logging.h"

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"
#include "wolfssl/error-ssl.h"



#ifdef WOLFSSL_STATIC_MEMORY
static WOLFSSL_HEAP_HINT* wolfssl_heap;
extern uint8_t* wolfsslMemoryBuffer;
extern size_t wolfsslMemoryBufferSize;
#else
#define wolfssl_heap NULL
#endif


#define ERROR_OUT(error_code, ...) { \
                                        asl_log(ASL_LOG_LEVEL_ERR, __VA_ARGS__); \
                                        ret = error_code; \
                                        goto cleanup; \
                                   }



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

        struct
        {
        #ifdef HAVE_PKCS11
                Pkcs11Dev device;
                Pkcs11Token token;
        #endif
                char const* pin;
                int device_id;
                bool initialized;
        }
        long_term_crypto_module;

        struct
        {
        #ifdef HAVE_PKCS11
                Pkcs11Dev device;
        #endif
                bool initialized;
        }
        ephemeral_crypto_module;

#if defined(HAVE_SECRET_CALLBACK)
        char* keylog_file;
#endif
};


/* Data structure for an active session */
struct asl_session
{
        WOLFSSL* wolfssl_session;
        enum connection_state state;

        struct
        {
        #ifdef HAVE_PKCS11
                Pkcs11Token token;
        #endif
                int device_id;
                bool initialized;
        }
        ephemeral_crypto_session;

        struct
        {
                struct timespec start_time;
                struct timespec end_time;
                uint32_t tx_bytes;
                uint32_t rx_bytes;
        }
        handshake_metrics;
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
static int dev_id_counter_endpoint = 0;
static int dev_id_counter_session = 0;


/* Internal method declarations */
#if defined(WOLFSSL_USER_IO)
static int wolfssl_read_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
static int wolfssl_write_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
#endif
static int wolfssl_configure_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
static int wolfssl_configure_pkcs11_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config);
static int get_next_device_id_endpoint(void);
static int get_next_device_id_session(void);
#endif


#if defined(WOLFSSL_USER_IO)
static int wolfssl_read_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
        int socket = wolfSSL_get_fd(wolfssl);
        asl_session* session = (asl_session*) ctx;

        int ret = recv(socket, buffer, size, 0);

        if (ret == 0)
        {
                return WOLFSSL_CBIO_ERR_CONN_CLOSE;
        }
        else if (ret < 0)
        {
                int error;
        #ifdef _WIN32
                error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK)
                        return WOLFSSL_CBIO_ERR_WANT_READ;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        #else
                error = errno;
                if ((error == EAGAIN) || (error == EWOULDBLOCK))
                        return WOLFSSL_CBIO_ERR_WANT_READ;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        #endif
        }

        /* Update handshake metrics */
        if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
        {
                session->handshake_metrics.rx_bytes += ret;
        }

        return ret;
}

static int wolfssl_write_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
        int socket = wolfSSL_get_fd(wolfssl);
        asl_session* session = (asl_session*) ctx;

        int ret = send(socket, buffer, size, 0);

        if (ret < 0)
        {
                int error;
        #ifdef _WIN32
                error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK)
                        return WOLFSSL_CBIO_ERR_WANT_WRITE;
                else if (error == ECONNRESET)
                        return WOLFSSL_CBIO_ERR_CONN_RST;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        #else
                error = errno;

                if ((error == EAGAIN) || (error == EWOULDBLOCK))
                        return WOLFSSL_CBIO_ERR_WANT_WRITE;
                else if (error == ECONNRESET)
                         return WOLFSSL_CBIO_ERR_CONN_RST;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        #endif
        }

        /* Update handshake metrics */
        if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
        {
                session->handshake_metrics.tx_bytes += ret;
        }

        return ret;
}
#endif /* WOLFSSL_USER_IO */

#if defined(HAVE_SECRET_CALLBACK)
/* Callback function for TLS v1.3 secrets for use with Wireshark */
static int wolfssl_secret_callback(WOLFSSL* ssl, int id, const uint8_t* secret,
                                       int secretSz, void* ctx)
{
        int i;
        const char* str = NULL;
        uint8_t serverRandom[32];
        int serverRandomSz;
        FILE* fp = stderr;
        if (ctx)
        {
                fp = fopen((const char*)ctx, "a");
                if (fp == NULL)
                        return BAD_FUNC_ARG;
        }

        serverRandomSz = (int)wolfSSL_get_client_random(ssl, serverRandom,
                                                        sizeof(serverRandom));

        if (serverRandomSz <= 0)
        {
                return BAD_FUNC_ARG;
        }

        switch (id)
        {
                case CLIENT_EARLY_TRAFFIC_SECRET:
                        str = "CLIENT_EARLY_TRAFFIC_SECRET";
                        break;
                case EARLY_EXPORTER_SECRET:
                        str = "EARLY_EXPORTER_SECRET";
                        break;
                case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
                        str = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
                        break;
                case SERVER_HANDSHAKE_TRAFFIC_SECRET:
                        str = "SERVER_HANDSHAKE_TRAFFIC_SECRET";
                        break;
                case CLIENT_TRAFFIC_SECRET:
                        str = "CLIENT_TRAFFIC_SECRET_0";
                        break;
                case SERVER_TRAFFIC_SECRET:
                        str = "SERVER_TRAFFIC_SECRET_0";
                        break;
                case EXPORTER_SECRET:
                        str = "EXPORTER_SECRET";
                        break;
                default:
                        str = "UNKNOWN";
                        break;
        }

        fprintf(fp, "%s ", str);
        for (i = 0; i < (int)serverRandomSz; i++)
        {
                fprintf(fp, "%02x", serverRandom[i]);
        }
        fprintf(fp, " ");
        for (i = 0; i < secretSz; i++)
        {
                fprintf(fp, "%02x", secret[i]);
        }
        fprintf(fp, "\n");

        fclose(fp);

        return 0;
}
#endif /* HAVE_SECRET_CALLBACK */


/* Create the default config for the Agile Security Library (asl). */
asl_configuration asl_default_config(void)
{
        asl_configuration default_config = {0};

        default_config.logging_enabled = true;
        default_config.log_level = ASL_LOG_LEVEL_WRN;
        default_config.custom_log_callback = NULL;

        return default_config;
}


/* Create the default config for an asl endpoint. */
asl_endpoint_configuration asl_default_endpoint_config(void)
{
        asl_endpoint_configuration default_config = {0};

        default_config.mutual_authentication = true;
        default_config.no_encryption = false;
        default_config.hybrid_signature_mode = ASL_HYBRID_SIGNATURE_MODE_DEFAULT;
        default_config.key_exchange_method = ASL_KEX_DEFAULT;
        default_config.pkcs11.long_term_crypto_module.path = NULL;
        default_config.pkcs11.long_term_crypto_module.pin = NULL;
        default_config.pkcs11.ephemeral_crypto_module.path = NULL;
        default_config.device_certificate_chain.buffer = NULL;
        default_config.device_certificate_chain.size = 0;
        default_config.private_key.buffer = NULL;
        default_config.private_key.size = 0;
        default_config.private_key.additional_key_buffer = NULL;
        default_config.private_key.additional_key_size = 0;
        default_config.root_certificate.buffer = NULL;
        default_config.root_certificate.size = 0;
        default_config.keylog_file = NULL;

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

        /* Configure the logging interface */
        asl_set_custom_log_callback(config->custom_log_callback);
        asl_enable_logging(config->logging_enabled);
        asl_set_log_level(config->log_level);

        /* Initialize WolfSSL */
        ret = wolfSSL_Init();
        if (wolfssl_check_for_error(ret))
                return ASL_INTERNAL_ERROR;

#ifdef WOLFSSL_STATIC_MEMORY
        /* Load static memory to avoid malloc */
        if ((config->staticMemoryBuffer.buffer != NULL) && (config->staticMemoryBuffer.size > 0))
        {
                if (wc_LoadStaticMemory(&wolfssl_heap, config->staticMemoryBuffer.buffer,
                                        config->staticMemoryBuffer.size, WOLFMEM_GENERAL, 1) != 0)
                {
                        log_callback(ASL_LOG_LEVEL_ERR, "unable to load static memory");
                        return ASL_MEMORY_ERROR;
                }
        }
#endif

        return ASL_SUCCESS;
}


#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)

/* Configure the PKCS11 long-term crypto module for an endpoint.
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int wolfssl_configure_pkcs11_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
        int ret = 0;

        if ((endpoint == NULL) || (config == NULL))
                return ASL_ARGUMENT_ERROR;

        /* Load the PKCS#11 module library */
        if (endpoint->long_term_crypto_module.initialized == false)
        {
                asl_log(ASL_LOG_LEVEL_INF, "Initializing PKCS#11 module from %s",
                        config->pkcs11.long_term_crypto_module.path);

                /* Initialize the PKCS#11 library */
                ret = wc_Pkcs11_Initialize(&endpoint->long_term_crypto_module.device,
                                           config->pkcs11.long_term_crypto_module.path,
                                           wolfssl_heap);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 library: %d", ret);

                /* Check if a PIN is provided */
                int pin_length = 0;
                if (config->pkcs11.long_term_crypto_module.pin != NULL)
                        pin_length = strlen(config->pkcs11.long_term_crypto_module.pin);

                /* Initialize the token */
                ret = wc_Pkcs11Token_Init(&endpoint->long_term_crypto_module.token,
                                          &endpoint->long_term_crypto_module.device,
                                          -1, NULL,
                                          config->pkcs11.long_term_crypto_module.pin,
                                          pin_length);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 token: %d", ret);

                /* Register the device with WolfSSL */
                ret = wc_CryptoCb_RegisterDevice(endpoint->long_term_crypto_module.device_id,
                                                 wc_Pkcs11_CryptoDevCb,
                                                 &endpoint->long_term_crypto_module.token);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to register PKCS#11 callback: %d", ret);

                /* Create a persistent session with the secure element */
                ret = wc_Pkcs11Token_Open(&endpoint->long_term_crypto_module.token, 1);
                if (ret == 0)
                {
                        endpoint->long_term_crypto_module.initialized = true;
                        asl_log(ASL_LOG_LEVEL_INF, "PKCS#11 module initialized");
                }
                else
                {
                        endpoint->long_term_crypto_module.initialized = false;
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to open PKCS#11 token: %d", ret);
                }
        }

        return 0;

cleanup:
        wc_Pkcs11Token_Final(&endpoint->long_term_crypto_module.token);
        wc_Pkcs11_Finalize(&endpoint->long_term_crypto_module.device);

        return ret;
}


static int get_next_device_id_endpoint(void)
{
        int current_id = dev_id_counter_endpoint;

        dev_id_counter_endpoint = (dev_id_counter_endpoint + 1) % DEVICE_ID_MAX_ENDPOINT;

        return current_id + DEVICE_ID_OFFSET_ENDPOINT;
}


static int get_next_device_id_session(void)
{
        int current_id = dev_id_counter_session;

        dev_id_counter_session = (dev_id_counter_session + 1) % DEVICE_ID_MAX_SESSION;

        return current_id + DEVICE_ID_OFFSET_SESSION;
}

#endif /* KRITIS3M_ASL_ENABLE_PKCS11 */


/* Configure the new endpoint (role-independent configuration).
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int wolfssl_configure_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
        if ((endpoint == NULL) || (config == NULL))
                return ASL_ARGUMENT_ERROR;

        /* Only allow TLS version 1.3 */
        int ret = wolfSSL_CTX_SetMinVersion(endpoint->wolfssl_context, WOLFSSL_TLSV1_3);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to set minimum TLS version");

        /* Load root certificate */
        ret = wolfSSL_CTX_load_verify_buffer(endpoint->wolfssl_context,
                                             config->root_certificate.buffer,
                                             config->root_certificate.size,
                                             WOLFSSL_FILETYPE_PEM);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_CERTIFICATE_ERROR, "Unable to load root certificate");

        /* Load device certificate chain */
        if (config->device_certificate_chain.buffer != NULL)
        {
                ret = wolfSSL_CTX_use_certificate_chain_buffer_format(endpoint->wolfssl_context,
                                                                config->device_certificate_chain.buffer,
                                                                config->device_certificate_chain.size,
                                                                WOLFSSL_FILETYPE_PEM);
                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_CERTIFICATE_ERROR, "Unable to load device certificate chain");
        }

        /* Initialize the PKCS#11 module for ephemeral crypto usage */
        if (config->pkcs11.ephemeral_crypto_module.path != NULL)
        {
        #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                asl_log(ASL_LOG_LEVEL_INF, "Initializing PKCS#11 module from %s",
                        config->pkcs11.ephemeral_crypto_module.path);

                /* Initialize the PKCS#11 library */
                ret = wc_Pkcs11_Initialize(&endpoint->ephemeral_crypto_module.device,
                                           config->pkcs11.ephemeral_crypto_module.path,
                                           wolfssl_heap);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 library: %d", ret);

                endpoint->ephemeral_crypto_module.initialized = true;
        #else
                ERROR_OUT(ASL_PKCS11_ERROR, "PKCS#11 support is not compiled in, please compile with support enabled");
        #endif
        }

        /* Load the private key */
        bool privateKeyLoaded = false;
        if (config->private_key.buffer != NULL)
        {
                if (strncmp((char const*)config->private_key.buffer, PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        endpoint->long_term_crypto_module.device_id = get_next_device_id_endpoint();

                        /* Initialize the PKCS#11 module */
                        ret = wolfssl_configure_pkcs11_endpoint(endpoint, config);
                        if (ret != 0)
                                ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure long-term crypto module");

                        asl_log(ASL_LOG_LEVEL_DBG, "Using external private key with label \"%s\"",
                                (char const*) config->private_key.buffer + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Use keys on the secure element (this also loads the label for the alt key) */
                        ret = wolfSSL_CTX_use_PrivateKey_Label(endpoint->wolfssl_context,
                                                               (char const*) config->private_key.buffer + PKCS11_LABEL_IDENTIFIER_LEN,
                                                               endpoint->long_term_crypto_module.device_id);
                #else
                        ERROR_OUT(ASL_PKCS11_ERROR, "Secure element support is not compiled in, please compile with support enabled");
                #endif
                }
                else
                {
                        /* Load the private key from the buffer */
                        ret = wolfSSL_CTX_use_PrivateKey_buffer(endpoint->wolfssl_context,
                                                                config->private_key.buffer,
                                                                config->private_key.size,
                                                                WOLFSSL_FILETYPE_PEM);
                }
                privateKeyLoaded = true;

                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to load private key");
        }


#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Load the alternative private key */
        if (config->private_key.additional_key_buffer != NULL)
        {
                if (strncmp((char const*)config->private_key.additional_key_buffer, PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        if (endpoint->long_term_crypto_module.device_id == INVALID_DEVID)
                                endpoint->long_term_crypto_module.device_id = get_next_device_id_endpoint();

                        /* Initialize the PKCS#11 module */
                        ret = wolfssl_configure_pkcs11_endpoint(endpoint, config);
                        if (ret != 0)
                                ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure long-term crypto module");

                        asl_log(ASL_LOG_LEVEL_DBG, "Using external alternative private key with label \"%s\"",
                                (char const*) config->private_key.additional_key_buffer + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Use keys on the secure element (this also loads the label for the alt key) */
                        ret = wolfSSL_CTX_use_AltPrivateKey_Label(endpoint->wolfssl_context,
                                        (char const*) config->private_key.additional_key_buffer + PKCS11_LABEL_IDENTIFIER_LEN,
                                        endpoint->long_term_crypto_module.device_id);
                #else
                        ERROR_OUT(ASL_PKCS11_ERROR, "Secure element support is not compiled in, please compile with support enabled");
                #endif
                }
                else
                {
                        /* Load the alternative private key from the buffer */
                        ret = wolfSSL_CTX_use_AltPrivateKey_buffer(endpoint->wolfssl_context,
                                                                   config->private_key.additional_key_buffer,
                                                                   config->private_key.additional_key_size,
                                                                   WOLFSSL_FILETYPE_PEM);
                }

                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to load alternative private key");
        }
#endif

        /* Check if the private key and the device certificate match */
#if !defined(__ZEPHYR__)
        if (privateKeyLoaded == true)
        {
        	ret = wolfSSL_CTX_check_private_key(endpoint->wolfssl_context);
        	if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_INTERNAL_ERROR, "Private key and device certificate do not match");
        }
#endif

        /* Set the IO callbacks for send and receive */
#if defined(WOLFSSL_USER_IO)
        wolfSSL_CTX_SetIORecv(endpoint->wolfssl_context, wolfssl_read_callback);
        wolfSSL_CTX_SetIOSend(endpoint->wolfssl_context, wolfssl_write_callback);
#endif

        /* Configure peer authentification */
        int verify_mode = WOLFSSL_VERIFY_NONE;
        if (config->mutual_authentication == true)
        {
                verify_mode = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        wolfSSL_CTX_set_verify(endpoint->wolfssl_context, verify_mode, NULL);

        return ASL_SUCCESS;

cleanup:
        return ret;
}


/* Setup a TLS server endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
asl_endpoint* asl_setup_server_endpoint(asl_endpoint_configuration const* config)
{
        int ret = 0;

        if (config == NULL)
                return NULL;

        /* Create a new endpoint object */
        asl_endpoint* new_endpoint = malloc(sizeof(asl_endpoint));
        if (new_endpoint == NULL)
                ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for new WolfSSL endpoint");

        new_endpoint->long_term_crypto_module.initialized = false;
        new_endpoint->ephemeral_crypto_module.initialized = false;
        new_endpoint->long_term_crypto_module.device_id = INVALID_DEVID;

#if defined(HAVE_SECRET_CALLBACK)
        if (config->keylog_file != NULL)
        {
                new_endpoint->keylog_file = (char*) malloc(strlen(config->keylog_file) + 1);
                if (new_endpoint->keylog_file == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for keylog file name");

                strcpy(new_endpoint->keylog_file, config->keylog_file);
        }
        else
                new_endpoint->keylog_file = NULL;
#endif

        /* Create the TLS server context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(wolfssl_heap), wolfssl_heap);
        if (new_endpoint->wolfssl_context == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL server context");

        /* Configure the new endpoint */
        ret = wolfssl_configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure new TLS server context");

        /* Configure the available curves for Key Exchange. For the server, all are allowed to
         * support various clients. */
        int wolfssl_key_exchange_curves[] = {
                WOLFSSL_P521_KYBER_LEVEL5,
                WOLFSSL_P384_KYBER_LEVEL5,
                WOLFSSL_KYBER_LEVEL5,
                WOLFSSL_ECC_SECP521R1,

                WOLFSSL_X448_KYBER_LEVEL3,
                WOLFSSL_P384_KYBER_LEVEL3,
                WOLFSSL_X25519_KYBER_LEVEL3,
                WOLFSSL_P256_KYBER_LEVEL3,
                WOLFSSL_KYBER_LEVEL3,
                WOLFSSL_ECC_X448,
                WOLFSSL_ECC_SECP384R1,

                WOLFSSL_X25519_KYBER_LEVEL1,
                WOLFSSL_P256_KYBER_LEVEL1,
                WOLFSSL_KYBER_LEVEL1,
                WOLFSSL_ECC_X25519,
                WOLFSSL_ECC_SECP256R1,
        };
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context, wolfssl_key_exchange_curves,
                                     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure key exchange curves");

        /* Configure the available cipher suites for TLS 1.3
         * We only support AES GCM with 256 bit key length and the
         * integrity only cipher with SHA384.
         */
        ret = wolfSSL_CTX_set_cipher_list(new_endpoint->wolfssl_context,
                                "TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384");
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure cipher suites");

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the preference for verfication of hybrid signatures to be for both the
         * native and alternative chains.
         */
        static uint8_t cks_order[] = {
            WOLFSSL_CKS_SIGSPEC_BOTH,
            WOLFSSL_CKS_SIGSPEC_NATIVE,
            WOLFSSL_CKS_SIGSPEC_ALTERNATIVE
        };

        ret = wolfSSL_CTX_UseCKS(new_endpoint->wolfssl_context, cks_order, sizeof(cks_order));
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure hybrid signature verification");
#endif

        return new_endpoint;

cleanup:
        asl_free_endpoint(new_endpoint);

        return NULL;
}


/* Setup a TLS client endpoint.
 *
 * Parameter is a pointer to a filled endpoint_configuration structure.
 *
 * Return value is a pointer to the newly created endpoint or NULL in case of an error
 * (error message is logged to the console).
 */
asl_endpoint* asl_setup_client_endpoint(asl_endpoint_configuration const* config)
{
        int ret = 0;

        if (config == NULL)
                return NULL;

        /* Create a new endpoint object */
        asl_endpoint* new_endpoint = malloc(sizeof(asl_endpoint));
        if (new_endpoint == NULL)
                ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for new WolfSSL endpoint");

        new_endpoint->long_term_crypto_module.initialized = false;
        new_endpoint->ephemeral_crypto_module.initialized = false;
        new_endpoint->long_term_crypto_module.device_id = INVALID_DEVID;

#if defined(HAVE_SECRET_CALLBACK)
        if (config->keylog_file != NULL)
        {
                new_endpoint->keylog_file = (char*) malloc(strlen(config->keylog_file) + 1);
                if (new_endpoint->keylog_file == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for keylog file name");

                strcpy(new_endpoint->keylog_file, config->keylog_file);
        }
        else
                new_endpoint->keylog_file = NULL;
#endif

        /* Create the TLS client context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(wolfssl_heap), wolfssl_heap);
        if (new_endpoint->wolfssl_context == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL client context");

        /* Configure the new endpoint */
        ret = wolfssl_configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure new TLS client context");

        /* Configure the curve for Key Exchange. For the client, we allowd only the one we want
         * to select (as the key share in the ClientHello is directly derived from it). If no
         * user supplied value is present, we select the hybrid level 3 one. */
        int wolfssl_key_exchange_curve = WOLFSSL_P384_KYBER_LEVEL3;
        if (config->key_exchange_method != ASL_KEX_DEFAULT)
        {
                switch (config->key_exchange_method)
                {
                        case ASL_KEX_CLASSIC_SECP256:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP256R1;
                                break;
                        case ASL_KEX_CLASSIC_SECP384:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP384R1;
                                break;
                        case ASL_KEX_CLASSIC_SECP521:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP521R1;
                                break;
                        case ASL_KEX_CLASSIC_X25519:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_X25519;
                                break;
                        case ASL_KEX_CLASSIC_X448:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_X448;
                                break;
                        case ASL_KEX_PQC_MLKEM512:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL1;
                                break;
                        case ASL_KEX_PQC_MLKEM768:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL3;
                                break;
                        case ASL_KEX_PQC_MLKEM1024:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL5;
                                break;
                        case ASL_KEX_HYBRID_SECP256_MLKEM512:
                                wolfssl_key_exchange_curve = WOLFSSL_P256_KYBER_LEVEL1;
                                break;
                        case ASL_KEX_HYBRID_SECP256_MLKEM768:
                                wolfssl_key_exchange_curve = WOLFSSL_P256_KYBER_LEVEL3;
                                break;
                        case ASL_KEX_HYBRID_SECP521_MLKEM1024:
                                wolfssl_key_exchange_curve = WOLFSSL_P521_KYBER_LEVEL5;
                                break;
                        case ASL_KEX_HYBRID_SECP384_MLKEM1024:
                                wolfssl_key_exchange_curve = WOLFSSL_P384_KYBER_LEVEL5;
                                break;
                        case ASL_KEX_HYBRID_X25519_MLKEM512:
                                wolfssl_key_exchange_curve = WOLFSSL_X25519_KYBER_LEVEL1;
                                break;
                        case ASL_KEX_HYBRID_X448_MLKEM768:
                                wolfssl_key_exchange_curve = WOLFSSL_X448_KYBER_LEVEL3;
                                break;
                        case ASL_KEX_HYBRID_X25519_MLKEM768:
                                wolfssl_key_exchange_curve = WOLFSSL_X25519_KYBER_LEVEL3;
                                break;
                        case ASL_KEX_HYBRID_SECP384_MLKEM768: /* Order change for default! */
                        default:
                                wolfssl_key_exchange_curve = WOLFSSL_P384_KYBER_LEVEL3;
                                break;

                }
        }
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context, &wolfssl_key_exchange_curve, 1);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure key exchange curve");

        /* Configure the available cipher suites for TLS 1.3
         * We only support AES GCM with 256 bit key length and the
         * integrity only cipher with SHA384.
         */
        char const* cipher_list = "TLS13-AES256-GCM-SHA384";
        if (config->no_encryption)
                cipher_list = "TLS13-SHA384-SHA384";

        ret = wolfSSL_CTX_set_cipher_list(new_endpoint->wolfssl_context, cipher_list);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure cipher suites");

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Set the preference for verfication of hybrid signatures. If the user has not
         * specified a preference, we default to BOTH. */
        static uint8_t cks[] = {WOLFSSL_CKS_SIGSPEC_BOTH};
        if (config->hybrid_signature_mode != ASL_HYBRID_SIGNATURE_MODE_DEFAULT)
        {
                switch (config->hybrid_signature_mode)
                {
                        case ASL_HYBRID_SIGNATURE_MODE_NATIVE:
                                cks[0] = WOLFSSL_CKS_SIGSPEC_NATIVE;
                                break;
                        case ASL_HYBRID_SIGNATURE_MODE_ALTERNATIVE:
                                cks[0] = WOLFSSL_CKS_SIGSPEC_ALTERNATIVE;
                                break;
                        case ASL_HYBRID_SIGNATURE_MODE_BOTH:
                        default:
                                cks[0] = WOLFSSL_CKS_SIGSPEC_BOTH;
                                break;
                };
        }
        ret = wolfSSL_CTX_UseCKS(new_endpoint->wolfssl_context, cks, sizeof(cks));
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure hybrid signature verification");
#endif

        return new_endpoint;

cleanup:
        asl_free_endpoint(new_endpoint);

        return NULL;
}


/* Create a new session for the endpoint.
 *
 * Parameters are a pointer to a configured endpoint and the socket fd of the underlying
 * network connection.
 *
 * Return value is a pointer to the newly created session or NULL in case of an error
 * (error message is logged to the console).
 */
asl_session* asl_create_session(asl_endpoint* endpoint, int socket_fd)
{
        int ret = 0;

        if (endpoint == NULL)
                 return NULL;

        /* Create a new session object */
        asl_session* new_session = malloc(sizeof(asl_session));
        if (new_session == NULL)
                ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for new WolfSSL session");

        new_session->state = CONNECTION_STATE_NOT_CONNECTED;
        new_session->ephemeral_crypto_session.initialized = false;
        new_session->ephemeral_crypto_session.device_id = INVALID_DEVID;

        /* Create a new TLS session */
        new_session->wolfssl_session = wolfSSL_new(endpoint->wolfssl_context);
        if (new_session->wolfssl_session == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL session");

        /* Initialize PKCS#11 module for ephemeral crypto */
        if (endpoint->ephemeral_crypto_module.initialized == true)
        {
        #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                new_session->ephemeral_crypto_session.device_id = get_next_device_id_session();

                /* Initialize the token */
                ret = wc_Pkcs11Token_Init_NoLogin(&new_session->ephemeral_crypto_session.token,
                                                      &endpoint->ephemeral_crypto_module.device,
                                                      -1, NULL);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 token: %d", ret);

                /* Register the device with WolfSSL */
                ret = wc_CryptoCb_RegisterDevice(new_session->ephemeral_crypto_session.device_id,
                                                 wc_Pkcs11_CryptoDevCb,
                                                 &new_session->ephemeral_crypto_session.token);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to register PKCS#11 callback: %d", ret);

                /* Create a persistent session with the secure element */
                ret = wc_Pkcs11Token_Open(&new_session->ephemeral_crypto_session.token, 1);
                if (ret == 0)
                {
                        new_session->ephemeral_crypto_session.initialized = true;
                        asl_log(ASL_LOG_LEVEL_INF, "PKCS#11 module initialized");
                }
                else
                {
                        new_session->ephemeral_crypto_session.initialized = false;
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to open PKCS#11 token: %d", ret);
                }

                wolfSSL_SetDevId(new_session->wolfssl_session,
                                 new_session->ephemeral_crypto_session.device_id);

        #else
                ERROR_OUT(ASL_PKCS11_ERROR, "PKCS#11 support is not compiled in, please compile with support enabled");
        #endif
        }


        /* Initialize the remaining attributes */
        new_session->state = CONNECTION_STATE_NOT_CONNECTED;
        new_session->handshake_metrics.tx_bytes = 0;
        new_session->handshake_metrics.rx_bytes = 0;

        /* Store the socket fd */
        wolfSSL_set_fd(new_session->wolfssl_session, socket_fd);

#if defined(WOLFSSL_USER_IO)
        /* Store a pointer to our session object to get access to the metrics from
         * the read and write callback. This must be done AFTER the call to
         * wolfSSL_set_fd() as this method overwrites the ctx variables.
         */
        wolfSSL_SetIOReadCtx(new_session->wolfssl_session, new_session);
        wolfSSL_SetIOWriteCtx(new_session->wolfssl_session, new_session);
#endif

#if defined(HAVE_SECRET_CALLBACK)
        if (endpoint->keylog_file != NULL)
        {
                /* required for getting random used */
                wolfSSL_KeepArrays(new_session->wolfssl_session);

                /* optional logging for wireshark */
                wolfSSL_set_tls13_secret_cb(new_session->wolfssl_session,
                                            wolfssl_secret_callback,
                                            (void*)endpoint->keylog_file);
        }
#endif

        return new_session;

cleanup:
        asl_free_session(new_session);

        return NULL;
}


/* Perform the TLS handshake for a newly created session.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged to
 * the console). In case the handshake is not done yet and you have to call the method again
 * when new data from the peer is present, ASL_WANT_READ is returned.
 */
int asl_handshake(asl_session* session)
{
        int ret = -1;

        if (session == NULL)
                return ASL_ARGUMENT_ERROR;

        /* Obtain handshake metrics */
        if (session->state == CONNECTION_STATE_NOT_CONNECTED)
        {
                session->state = CONNECTION_STATE_HANDSHAKE;

                /* Get start time */
                if (clock_gettime(CLOCK_MONOTONIC,
                                  &session->handshake_metrics.start_time) != 0)
                        asl_log(ASL_LOG_LEVEL_WRN, "Error starting handshake timer");
        }

        while (ret != 0)
        {
                ret = wolfSSL_negotiate(session->wolfssl_session);

                if (ret == WOLFSSL_SUCCESS)
                {
                        session->state = CONNECTION_STATE_CONNECTED;

                        /* Get end time */
                        if (clock_gettime(CLOCK_MONOTONIC,
                                        &session->handshake_metrics.end_time) != 0)
                                asl_log(ASL_LOG_LEVEL_WRN, "Error stopping handshake timer");

                #ifdef HAVE_SECRET_CALLBACK
                        wolfSSL_FreeArrays(session->wolfssl_session);
                #endif

                        ret = ASL_SUCCESS;
                        break;
                }
                else
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                ret = ASL_WANT_READ;
                                break;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* Unable to write data, indicate to higher layers */
                                ret = ASL_WANT_WRITE;
                                break;
                        }
                        else
                        {
                                char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                asl_log(ASL_LOG_LEVEL_ERR, "TLS handshake failed: %s", errMsg);
                                ret = ASL_INTERNAL_ERROR;
                                break;
                        }
                }
        }

        return ret;
}


/* Receive new data from the TLS peer.
 *
 * Returns the number of received bytes on success, negative error code on failure
 * (error message is logged to the console). In case we have not received enough data
 * to decode the TLS record, ASL_WANT_READ is returned. In that case, you have to call
 * the method again when new data from the peer is present.
 */
int asl_receive(asl_session* session, uint8_t* buffer, int max_size)
{
        uint8_t* tmp = buffer;
        int bytes_read = 0;

        if (session == NULL)
        {
                return ASL_ARGUMENT_ERROR;
        }

        while (1)
        {
                int ret = wolfSSL_read(session->wolfssl_session, tmp, max_size - bytes_read);

                if (ret <= 0)
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* Unable to write data, indicate to higher layers */
                                bytes_read = ASL_WANT_WRITE;
                                break;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* No more data, we have to asynchronously wait for new */
                                bytes_read = ASL_WANT_READ;
                                break;
                        }
                        else if ((ret == WOLFSSL_ERROR_ZERO_RETURN) || (ret == WOLFSSL_ERROR_SYSCALL))
                        {
                                bytes_read = ASL_CONN_CLOSED;
                                break;
                        }
                        else
                        {
                                char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                asl_log(ASL_LOG_LEVEL_ERR, "wolfSSL_read returned %d: %s", ret, errMsg);
                                bytes_read = ASL_INTERNAL_ERROR;
                                break;
                        }
                }

                /* It is technically possible to call asl_receive() and asl_send() without performing the
                 * TLS handshake via asl_handshake(). Although this is discouraged, we do not prevent it.
                 * However, we have to properly handle internal state here, mainly to free any handshake
                 * buffers. As soon as wolfssl_read() or wolfssl_write() return a successful return code,
                 * we are sure to finished the TLS handshake. Hence, we can update the state here safely.
                 */
                if (session->state != CONNECTION_STATE_CONNECTED)
                {
                        session->state = CONNECTION_STATE_CONNECTED;

                #ifdef HAVE_SECRET_CALLBACK
                        wolfSSL_FreeArrays(session->wolfssl_session);
                #endif
                }

                tmp += ret;
                bytes_read += ret;

                break;
        }

        return bytes_read;
}


/* Send data to the TLS remote peer.
 *
 * Returns ASL_SUCCESS on success, negative error code on failure (error message is logged
 * to the console). In case we cannot write the data in one call, ASL_WANT_WRITE is returned,
 * indicating that you have to call the method again (with the same data!) once the socket is
 * writable again.
 */
int asl_send(asl_session* session, uint8_t const* buffer, int size)
{
        uint8_t const* tmp = buffer;
        int ret = ASL_SUCCESS;

        if (session == NULL)
        {
                return ASL_ARGUMENT_ERROR;
        }

        while (size > 0)
        {
                ret = wolfSSL_write(session->wolfssl_session, tmp, size);

                if (ret > 0)
                {
                        /* We successfully sent data */
                        size -= ret;
                        tmp += ret;
                        ret = ASL_SUCCESS;

                        /* It is technically possible to call asl_receive() and asl_send() without performing the
                        * TLS handshake via asl_handshake(). Although this is discouraged, we do not prevent it.
                        * However, we have to properly handle internal state here, mainly to free any handshake
                        * buffers. As soon as wolfssl_read() or wolfssl_write() return a successful return code,
                        * we are sure to finished the TLS handshake. Hence, we can update the state here safely.
                        */
                        if (session->state != CONNECTION_STATE_CONNECTED)
                        {
                                session->state = CONNECTION_STATE_CONNECTED;

                        #ifdef HAVE_SECRET_CALLBACK
                                wolfSSL_FreeArrays(session->wolfssl_session);
                        #endif
                        }
                }
                else
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                        if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* We have to first receive data from the peer. In this case,
                                 * we discard the data and continue reading data from it. */
                                ret = ASL_WANT_READ;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* We have more to write, but obviously the socket can't handle
                                 * it right now. */
                                ret = ASL_WANT_WRITE;
                        }
                        else if (ret == WOLFSSL_ERROR_SYSCALL)
                        {
                                ret = ASL_CONN_CLOSED;
                        }
                        else
                        {
                                if (ret != 0)
                                {
                                        char errMsg[WOLFSSL_MAX_ERROR_SZ];
                                        wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                                        asl_log(ASL_LOG_LEVEL_ERR, "wolfSSL_write returned %d: %s", ret, errMsg);
                                }
                                ret = ASL_INTERNAL_ERROR;
                        }

                        break;
                }
        }

        return ret;
}

/* Get metics of the handshake. */
asl_handshake_metrics asl_get_handshake_metrics(asl_session* session)
{
        asl_handshake_metrics metrics = {
                .duration_us = 0.0,
                .tx_bytes = 0,
                .rx_bytes = 0
        };

        if (session != NULL)
        {
                uint32_t secs = session->handshake_metrics.end_time.tv_sec - session->handshake_metrics.start_time.tv_sec;
                uint32_t nsecs = session->handshake_metrics.end_time.tv_nsec - session->handshake_metrics.start_time.tv_nsec;

                metrics.duration_us = secs * 1000000 + nsecs / 1000;
                metrics.tx_bytes = session->handshake_metrics.tx_bytes;
                metrics.rx_bytes = session->handshake_metrics.rx_bytes;
        }

        return metrics;
}


/* Close the connection of the active session */
void asl_close_session(asl_session* session)
{
        if (session != NULL)
        {
                wolfSSL_shutdown(session->wolfssl_session);
                session->state = CONNECTION_STATE_NOT_CONNECTED;
        }
}


/* Free ressources of a session. */
void asl_free_session(asl_session* session)
{
        if (session != NULL)
        {
                if (session->wolfssl_session != NULL)
                        wolfSSL_free(session->wolfssl_session);

                if (session->ephemeral_crypto_session.initialized == true)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                         wc_Pkcs11Token_Final(&session->ephemeral_crypto_session.token);
                         wc_CryptoCb_UnRegisterDevice(session->ephemeral_crypto_session.device_id);
                #endif
                }

                free(session);
        }
}


/* Free ressources of an endpoint. */
void asl_free_endpoint(asl_endpoint* endpoint)
{
        if (endpoint != NULL)
        {
                /* Properly cleanup PKCS#11 stuff */
                if (endpoint->long_term_crypto_module.initialized == true)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        wc_Pkcs11Token_Final(&endpoint->long_term_crypto_module.token);
                        wc_Pkcs11_Finalize(&endpoint->long_term_crypto_module.device);
                        wc_CryptoCb_UnRegisterDevice(endpoint->long_term_crypto_module.device_id);
                #endif
                }
                if (endpoint->ephemeral_crypto_module.initialized == true)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        wc_Pkcs11_Finalize(&endpoint->ephemeral_crypto_module.device);
                #endif
                }

                /* Free the WolfSSL context */
                if (endpoint->wolfssl_context != NULL)
                        wolfSSL_CTX_free(endpoint->wolfssl_context);

        #if defined(HAVE_SECRET_CALLBACK)
                if (endpoint->keylog_file != NULL)
                        free(endpoint->keylog_file);
        #endif

                free(endpoint);
        }
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
                default:
                        errMsg = "Unknown error";
                        break;
        }

        return errMsg;
}


/* Access to the internal WolfSSL API */
#if defined(KRITIS3M_ASL_INTERNAL_API)

/* Get the internal WolfSSL CTX object */
WOLFSSL_CTX* asl_get_wolfssl_context(asl_endpoint* endpoint)
{
        if (endpoint == NULL)
                return NULL;

        return endpoint->wolfssl_context;
}

/* Get the internal WolfSSL session object */
WOLFSSL* asl_get_wolfssl_session(asl_session* session)
{
        if (session == NULL)
                return NULL;

        return session->wolfssl_session;
}

#endif


/* Cleanup any library resources */
void asl_cleanup(void)
{
        /* Cleanup WolfSSL */
        wolfSSL_Cleanup();

        /* Nothing more to do at the moment... */
}

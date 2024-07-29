
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>

#include "asl.h"
#include "asl_logging.h"

#include "wolfssl/wolfcrypt/settings.h"
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


enum connection_state
{
        CONNECTION_STATE_NOT_CONNECTED,
        CONNECTION_STATE_HANDSHAKE,
        CONNECTION_STATE_CONNECTED,
};


/* PKCS#11 support */
#define DEVICE_ID_SECURE_ELEMENT 1

typedef struct
{
#ifdef HAVE_PKCS11
	Pkcs11Dev device;
	Pkcs11Token token;
#endif
	bool initialized;
}
asl_pkcs11_module;


/* Data structure for an endpoint */
struct asl_endpoint
{
        WOLFSSL_CTX* wolfssl_context;
        asl_pkcs11_module secure_element;

#if defined(HAVE_SECRET_CALLBACK)
        char const* keylog_file;
#endif
};


/* Data structure for an active session */
struct asl_session
{
        WOLFSSL* wolfssl_session;
        enum connection_state state;

        struct
        {
                struct timespec start_time;
                struct timespec end_time;
                uint32_t tx_bytes;
                uint32_t rx_bytes;
        }
        handshake_metrics_priv;
};


/* Internal method declarations */
static int wolfssl_read_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
static int wolfssl_write_callback(WOLFSSL* session, char* buffer, int size, void* ctx);
static int wolfssl_configure_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
static int wolfssl_configure_pkcs11(asl_pkcs11_module* module, char const* path);
#endif


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
                int error = errno;
                if ((error == EAGAIN) || (error == EWOULDBLOCK))
                        return WOLFSSL_CBIO_ERR_WANT_READ;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* Update handshake metrics */
        if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
        {
                session->handshake_metrics_priv.rx_bytes += ret;
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
                int error = errno;
                if ((error == EAGAIN) || (error == EWOULDBLOCK))
                        return WOLFSSL_CBIO_ERR_WANT_WRITE;
                else if (error == ECONNRESET)
                        return WOLFSSL_CBIO_ERR_CONN_RST;
                else
                        return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* Update handshake metrics */
        if (session != NULL && session->state == CONNECTION_STATE_HANDSHAKE)
        {
                session->handshake_metrics_priv.tx_bytes += ret;
        }

        return ret;
}


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
                {
                        return BAD_FUNC_ARG;
                }
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

        if (fp != stderr)
        {
                fclose(fp);
        }

        return 0;
}
#endif /* HAVE_SECRET_CALLBACK */


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

/* Configure a PKCS11 module for an endpoint.
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int wolfssl_configure_pkcs11(asl_pkcs11_module* module, char const* path)
{
        int ret = 0;

        if ((module == NULL) || (path == NULL))
        {
                return ASL_ARGUMENT_ERROR;
        }

        /* Load the secure element middleware */
        if (module->initialized == false)
        {
                asl_log(ASL_LOG_LEVEL_INF, "Initializing secure element");

                /* Initialize the PKCS#11 library */
                ret = wc_Pkcs11_Initialize(&module->device, path, wolfssl_heap);
                if (ret != 0)
                {
                        asl_log(ASL_LOG_LEVEL_ERR, "unable to initialize PKCS#11 library: %d", ret);
                        return ASL_PKCS11_ERROR;
                }

                /* Initialize the token */
                ret = wc_Pkcs11Token_Init_NoLogin(&module->token, &module->device, -1, NULL);
                if (ret != 0)
                {
                        asl_log(ASL_LOG_LEVEL_ERR, "unable to initialize PKCS#11 token: %d", ret);
                        wc_Pkcs11_Finalize(&module->device);
                        return ASL_PKCS11_ERROR;
                }

                /* Register the device with WolfSSL */
                ret = wc_CryptoCb_RegisterDevice(DEVICE_ID_SECURE_ELEMENT,
                                                 wc_Pkcs11_CryptoDevCb,
                                                 &module->token);
                if (ret != 0)
                {
                        asl_log(ASL_LOG_LEVEL_ERR, "Failed to register PKCS#11 callback: %d", ret);
                        wc_Pkcs11Token_Final(&module->token);
                        wc_Pkcs11_Finalize(&module->device);
                        return ASL_PKCS11_ERROR;
                }

                /* Create a persistent session with the secure element */
                ret = wc_Pkcs11Token_Open(&module->token, 1);
                if (ret == 0)
                {
                        module->initialized = true;
                        asl_log(ASL_LOG_LEVEL_INF, "Secure element initialized");
                }
                else
                {
                        module->initialized = false;
                        wc_Pkcs11Token_Final(&module->token);
                        wc_Pkcs11_Finalize(&module->device);
                        asl_log(ASL_LOG_LEVEL_ERR, "Secure element initialization failed: %d", ret);
                        return ASL_PKCS11_ERROR;
                }
        }

        return ret;
}

#endif /* KRITIS3M_ASL_ENABLE_PKCS11 */


/* Configure the new endpoint (role-independent configuration).
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int wolfssl_configure_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
        /* Only allow TLS version 1.3 */
        int ret = wolfSSL_CTX_SetMinVersion(endpoint->wolfssl_context, WOLFSSL_TLSV1_3);
        if (wolfssl_check_for_error(ret))
                return ASL_INTERNAL_ERROR;

        /* Load root certificate */
        ret = wolfSSL_CTX_load_verify_buffer(endpoint->wolfssl_context,
                                             config->root_certificate.buffer,
                                             config->root_certificate.size,
                                             WOLFSSL_FILETYPE_PEM);
        if (wolfssl_check_for_error(ret))
                return ASL_CERTIFICATE_ERROR;

        /* Load device certificate chain */
        if (config->device_certificate_chain.buffer != NULL)
        {
                ret = wolfSSL_CTX_use_certificate_chain_buffer_format(endpoint->wolfssl_context,
                                                                config->device_certificate_chain.buffer,
                                                                config->device_certificate_chain.size,
                                                                WOLFSSL_FILETYPE_PEM);
                if (wolfssl_check_for_error(ret))
                        return ASL_CERTIFICATE_ERROR;
        }

        /* Load the private key */
        bool privateKeyLoaded = false;
        if (config->private_key.buffer != NULL)
        {
                if (strncmp((char const*)config->private_key.buffer, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        /* Initialize the PKCS#11 module */
                        ret = wolfssl_configure_pkcs11(&endpoint->secure_element, config->secure_element_middleware_path);
                        if (ret != 0)
                        {
                                asl_log(ASL_LOG_LEVEL_ERR, "Failed to configure secure element");
                                return ASL_PKCS11_ERROR;
                        }

                        // wolfSSL_CTX_SetDevId(context, DEVICE_ID_SECURE_ELEMENT);

                        asl_log(ASL_LOG_LEVEL_DBG, "Using external private key with label \"%s\"",
                                (char const*) config->private_key.buffer + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Use keys on the secure element (this also loads the label for the alt key) */
                        ret = wolfSSL_CTX_use_PrivateKey_Label(endpoint->wolfssl_context,
                                                               (char const*) config->private_key.buffer + PKCS11_LABEL_IDENTIFIER_LEN,
                                                               DEVICE_ID_SECURE_ELEMENT);

                        privateKeyLoaded = true;
                #else
                        asl_log(ASL_LOG_LEVEL_ERR, "Secure element support is not compiled in, please compile with support enabled");
                        return ASL_PKCS11_ERROR;
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

                if (wolfssl_check_for_error(ret))
                        return ASL_INTERNAL_ERROR;
        }


#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Load the alternative private key */
        if (config->private_key.additional_key_buffer != NULL)
        {
                if (strncmp((char const*)config->private_key.additional_key_buffer, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        /* Initialize the PKCS#11 module */
                        ret = wolfssl_configure_pkcs11(&endpoint->secure_element, config->secure_element_middleware_path);
                        if (ret != 0)
                        {
                                asl_log(ASL_LOG_LEVEL_ERR, "Failed to configure secure element");
                                return ASL_PKCS11_ERROR;
                        }

                        asl_log(ASL_LOG_LEVEL_DBG, "Using external alternative private key with label \"%s\"",
                                (char const*) config->private_key.additional_key_buffer + PKCS11_LABEL_IDENTIFIER_LEN);

                        /* Use keys on the secure element (this also loads the label for the alt key) */
                        ret = wolfSSL_CTX_use_AltPrivateKey_Label(endpoint->wolfssl_context,
                                        (char const*) config->private_key.additional_key_buffer + PKCS11_LABEL_IDENTIFIER_LEN,
                                        DEVICE_ID_SECURE_ELEMENT);
                #else
                        asl_log(ASL_LOG_LEVEL_ERR, "Secure element support is not compiled in, please compile with support enabled");
                        return ASL_PKCS11_ERROR;
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
                        return ASL_INTERNAL_ERROR;
        }
#endif

        /* Check if the private key and the device certificate match */
        if (privateKeyLoaded == true)
        {
        	ret = wolfSSL_CTX_check_private_key(endpoint->wolfssl_context);
        	if (wolfssl_check_for_error(ret))
        		return ASL_INTERNAL_ERROR;
        }

        /* Set the IO callbacks for send and receive */
        wolfSSL_CTX_SetIORecv(endpoint->wolfssl_context, wolfssl_read_callback);
        wolfSSL_CTX_SetIOSend(endpoint->wolfssl_context, wolfssl_write_callback);

        /* Configure peer authentification */
        int verify_mode = WOLFSSL_VERIFY_NONE;
        if (config->mutual_authentication == true)
        {
                verify_mode = WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        wolfSSL_CTX_set_verify(endpoint->wolfssl_context, verify_mode, NULL);

        return ASL_SUCCESS;
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
        if (config == NULL)
        {
                return NULL;
        }

        /* Create a new endpoint object */
        asl_endpoint* new_endpoint = malloc(sizeof(asl_endpoint));
        if (new_endpoint == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to allocate memory for new WolfSSL endpoint");
                return NULL;
        }

        new_endpoint->secure_element.initialized = false;
#if defined(HAVE_SECRET_CALLBACK)
        new_endpoint->keylog_file = config->keylog_file;
#endif

        /* Create the TLS server context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(wolfssl_heap), wolfssl_heap);
        if (new_endpoint->wolfssl_context == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to create a new WolfSSL server context");
                free(new_endpoint);
                return NULL;
        }

        /* Configure the new endpoint */
        int ret = wolfssl_configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Failed to configure new TLS server context: %s (%d)",
                        asl_error_message(ret), ret);
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

        /* Configure the available curves for Key Exchange. For the server, all are allowed to
         * support various clients. */
        int wolfssl_key_exchange_curves[] = {
                WOLFSSL_ECC_SECP256R1,
                WOLFSSL_ECC_SECP384R1,
                WOLFSSL_ECC_SECP521R1,
                WOLFSSL_KYBER_LEVEL1,
                WOLFSSL_KYBER_LEVEL3,
                WOLFSSL_KYBER_LEVEL5,
                WOLFSSL_P256_KYBER_LEVEL1,
                WOLFSSL_P384_KYBER_LEVEL3,
                WOLFSSL_P521_KYBER_LEVEL5,
        };
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context, wolfssl_key_exchange_curves,
                                     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
        if (wolfssl_check_for_error(ret))
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

        /* Configure the available cipher suites for TLS 1.3
         * We only support AES GCM with 256 bit key length and the
         * integrity only cipher with SHA384.
         */
        ret = wolfSSL_CTX_set_cipher_list(new_endpoint->wolfssl_context,
                                "TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384");
        if (wolfssl_check_for_error(ret))
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

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
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }
#endif

        return new_endpoint;
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
        if (config == NULL)
        {
                return NULL;
        }

        /* Create a new endpoint object */
        asl_endpoint* new_endpoint = malloc(sizeof(asl_endpoint));
        if (new_endpoint == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to allocate memory for new WolfSSL endpoint");
                return NULL;
        }

        new_endpoint->secure_element.initialized = false;
#if defined(HAVE_SECRET_CALLBACK)
        new_endpoint->keylog_file = config->keylog_file;
#endif

        /* Create the TLS client context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(wolfssl_heap), wolfssl_heap);
        if (new_endpoint->wolfssl_context == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to create a new WolfSSL client context");
                free(new_endpoint);
                return NULL;
        }

        /* Configure the new endpoint */
        int ret = wolfssl_configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Failed to confiugre new TLS client context: %s (%d)",
                        asl_error_message(ret), ret);
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

        /* Configure the curve for Key Exchange. For the client, we allowd only the one we want
         * to select (as the key share in the ClientHello is directly derived from it). If no
         * user supplied value is present, we select the hybrid level 3 one. */
        int wolfssl_key_exchange_curve = WOLFSSL_P384_KYBER_LEVEL3;
        if (config->key_exchange_method != ASL_KEX_DEFAULT)
        {
                switch (config->key_exchange_method)
                {
                        case ASL_KEX_CLASSIC_ECDHE_256:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP256R1;
                                break;
                        case ASL_KEX_CLASSIC_ECDHE_384:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP384R1;
                                break;
                        case ASL_KEX_CLASSIC_ECDHE_521:
                                wolfssl_key_exchange_curve = WOLFSSL_ECC_SECP521R1;
                                break;
                        case ASL_KEX_PQC_MLKEM_512:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL1;
                                break;
                        case ASL_KEX_PQC_MLKEM_768:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL3;
                                break;
                        case ASL_KEX_PQC_MLKEM_1024:
                                wolfssl_key_exchange_curve = WOLFSSL_KYBER_LEVEL5;
                                break;
                        case ASL_KEX_HYBRID_ECDHE_256_MLKEM_512:
                                wolfssl_key_exchange_curve = WOLFSSL_P256_KYBER_LEVEL1;
                                break;
                        case ASL_KEX_HYBRID_ECDHE_521_MLKEM_1024:
                                wolfssl_key_exchange_curve = WOLFSSL_P521_KYBER_LEVEL5;
                                break;
                        case ASL_KEX_HYBRID_ECDHE_384_MLKEM_768: /* Order change for default! */
                        default:
                                wolfssl_key_exchange_curve = WOLFSSL_P384_KYBER_LEVEL3;
                                break;

                }
        }
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context, &wolfssl_key_exchange_curve, 1);
        if (wolfssl_check_for_error(ret))
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

        /* Configure the available cipher suites for TLS 1.3
         * We only support AES GCM with 256 bit key length and the
         * integrity only cipher with SHA384.
         */
        char const* cipher_list = "TLS13-AES256-GCM-SHA384";
        if (config->no_encryption)
        {
                cipher_list = "TLS13-SHA384-SHA384";
        }
        ret = wolfSSL_CTX_set_cipher_list(new_endpoint->wolfssl_context, cipher_list);
        if (wolfssl_check_for_error(ret))
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }

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
        {
                wolfSSL_CTX_free(new_endpoint->wolfssl_context);
                free(new_endpoint);
                return NULL;
        }
#endif

        return new_endpoint;
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
        if (endpoint == NULL)
        {
                return NULL;
        }

        /* Create a new session object */
        asl_session* new_session = malloc(sizeof(asl_session));
        if (new_session == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to allocate memory for new WolfSSL session");
                return NULL;
        }

        /* Create a new TLS session */
        new_session->wolfssl_session = wolfSSL_new(endpoint->wolfssl_context);
        if (new_session->wolfssl_session == NULL)
        {
                asl_log(ASL_LOG_LEVEL_ERR, "Unable to create a new WolfSSL session");
                free(new_session);
                return NULL;
        }

        /* Initialize the remaining attributes */
        new_session->state = CONNECTION_STATE_NOT_CONNECTED;
        new_session->handshake_metrics_priv.tx_bytes = 0;
        new_session->handshake_metrics_priv.rx_bytes = 0;

        /* Store the socket fd */
        wolfSSL_set_fd(new_session->wolfssl_session, socket_fd);

        /* Store a pointer to our session object to get access to the metrics from
         * the read and write callback. This must be done AFTER the call to
         * wolfSSL_set_fd() as this method overwrites the ctx variables.
         */
        wolfSSL_SetIOReadCtx(new_session->wolfssl_session, new_session);
        wolfSSL_SetIOWriteCtx(new_session->wolfssl_session, new_session);

#ifdef HAVE_SECRET_CALLBACK
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
        {
                return ASL_ARGUMENT_ERROR;
        }

        /* Obtain handshake metrics */
        if (session->state == CONNECTION_STATE_NOT_CONNECTED)
        {
                session->state = CONNECTION_STATE_HANDSHAKE;

                /* Get start time */
                if (clock_gettime(CLOCK_MONOTONIC,
                                  &session->handshake_metrics_priv.start_time) != 0)
                {
                        asl_log(ASL_LOG_LEVEL_WRN, "Error starting handshake timer");
                }
        }

        while (ret != 0)
        {
                ret = wolfSSL_negotiate(session->wolfssl_session);

                if (ret == WOLFSSL_SUCCESS)
                {
                        session->state = CONNECTION_STATE_CONNECTED;

                        /* Get end time */
                        if (clock_gettime(CLOCK_MONOTONIC,
                                        &session->handshake_metrics_priv.end_time) != 0)
                        {
                                asl_log(ASL_LOG_LEVEL_WRN, "Error stopping handshake timer");
                        }

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
                                continue;
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
        int bytes_read = ASL_SUCCESS;

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
                                /* Call wolfSSL_read() again */
                                continue;
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
                }
                else
                {
                        ret = wolfSSL_get_error(session->wolfssl_session, ret);

                            if (ret == WOLFSSL_ERROR_WANT_READ)
                        {
                                /* We have to first receive data from the peer. In this case,
                                 * we discard the data and continue reading data from it. */
                                ret = ASL_WANT_READ;
                                break;
                        }
                        else if (ret == WOLFSSL_ERROR_WANT_WRITE)
                        {
                                /* We have more to write. */
                                continue;
                        }
                        else if (ret == WOLFSSL_ERROR_SYSCALL)
                        {
                                ret = ASL_CONN_CLOSED;
                                break;
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

                                break;
                        }
                }

        }

        return ret;
}

/* Get metics of the handshake. */
asl_handshake_metrics asl_get_handshake_metrics(asl_session* session)
{
        asl_handshake_metrics metrics;

        if (session != NULL)
        {
                metrics.duration_us = (session->handshake_metrics_priv.end_time.tv_sec - session->handshake_metrics_priv.start_time.tv_sec) * 1000000.0 +
                                (session->handshake_metrics_priv.end_time.tv_nsec - session->handshake_metrics_priv.start_time.tv_nsec) / 1000.0;
                metrics.tx_bytes = session->handshake_metrics_priv.tx_bytes;
                metrics.rx_bytes = session->handshake_metrics_priv.rx_bytes;
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
                {
                        wolfSSL_free(session->wolfssl_session);
                }

                free(session);
        }
}


/* Free ressources of an endpoint. */
void asl_free_endpoint(asl_endpoint* endpoint)
{
        if (endpoint != NULL)
        {
                /* Properly cleanup PKCS#11 stuff*/
                if (endpoint->secure_element.initialized == true)
                {
                #if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                        wc_Pkcs11Token_Final(&endpoint->secure_element.token);
                        wc_Pkcs11_Finalize(&endpoint->secure_element.device);
                #endif
                }

                /* Free the WolfSSL context */
                if (endpoint->wolfssl_context != NULL)
                {
                        wolfSSL_CTX_free(endpoint->wolfssl_context);
                }

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
        return endpoint->wolfssl_context;
}

/* Get the internal WolfSSL session object */
WOLFSSL* asl_get_wolfssl_session(asl_session* session)
{
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

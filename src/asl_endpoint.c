
#include <errno.h>
#include <stdlib.h>

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

#if defined(WOLFSSL_USER_IO)
static int wolfssl_read_callback(WOLFSSL* wolfssl, char* buffer, int size, void* ctx)
{
        int socket = wolfSSL_get_fd(wolfssl);
        asl_session* session = (asl_session*) ctx;

        int ret = recv(socket, buffer, size, 0);

        if (ret == 0)
        {
                printf("Connection closed by peer\n");
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

/* Configure the new endpoint (role-independent configuration).
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int configure_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
        int ret = 0;

        if ((endpoint == NULL) || (config == NULL))
                return ASL_ARGUMENT_ERROR;

        endpoint->ciphersuites = NULL;
        endpoint->pkcs11_module.initialized = false;
        endpoint->pkcs11_module.device_id = INVALID_DEVID;

#ifndef NO_PSK
        endpoint->psk.key = NULL;
        endpoint->psk.identity = NULL;
        endpoint->psk.use_external_callbacks = false;
        endpoint->psk.enable_cert_auth = true;
#endif
#if defined(HAVE_SECRET_CALLBACK)
        if (config->keylog_file != NULL)
        {
                endpoint->keylog_file = (char*) malloc(strlen(config->keylog_file) + 1);
                if (endpoint->keylog_file == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for keylog file name");

                strcpy(endpoint->keylog_file, config->keylog_file);
        }
        else
                endpoint->keylog_file = NULL;

#if !defined(__ZEPHYR__) && !defined(_WIN32)
        /* Check if the SSLKEYLOGFILE environment variable */
        if (endpoint->keylog_file == NULL)
        {
                char* env_keylog_file = getenv("SSLKEYLOGFILE");
                if (env_keylog_file != NULL)
                {
                        endpoint->keylog_file = (char*) malloc(strlen(env_keylog_file) + 1);
                        if (endpoint->keylog_file == NULL)
                                ERROR_OUT(ASL_MEMORY_ERROR,
                                          "Unable to allocate memory for keylog file name");

                        strcpy(endpoint->keylog_file, env_keylog_file);
                }
        }
#endif /* !__ZEPHYR && !_WIN32 */
#endif /* HAVE_SECRET_CALLBACK */

        /* Only allow TLS version 1.3 */
        ret = wolfSSL_CTX_SetMinVersion(endpoint->wolfssl_context, WOLFSSL_TLSV1_3);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to set minimum TLS version");

#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
        /* If we want to use a PKCS#11 token for all cryptographic operations, we have
         * to initialize the module. */
        if (config->pkcs11.use_for_all == true)
        {
                ret = configure_pkcs11_endpoint(endpoint, config);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure PKCS#11 crypto module");
        }
#endif /* KRITIS3M_ASL_ENABLE_PKCS11 && HAVE_PKCS11 */

        /* Load root certificate */
        if (config->root_certificate.buffer != NULL && config->root_certificate.size > 0)
        {
                /* Check for PKCS#11 identifier. `-1` on the IDENTIFIER_LEN to exclude the ":" at
                 * the end, as we don't have a label for root certs. */
                if (strncmp((char const*) config->root_certificate.buffer,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
                {
                        ret = use_pkcs11_root_certificates(endpoint, config);
                }
                /* Check if we have a PEM or DER file */
                else if (memcmp(config->root_certificate.buffer, "-----", 5) == 0)
                {
                        /* PEM file */
                        ret = wolfSSL_CTX_load_verify_buffer(endpoint->wolfssl_context,
                                                             config->root_certificate.buffer,
                                                             config->root_certificate.size,
                                                             WOLFSSL_FILETYPE_PEM);
                }
                else
                {
                        /* DER file */
                        ret = wolfSSL_CTX_load_verify_buffer(endpoint->wolfssl_context,
                                                             config->root_certificate.buffer,
                                                             config->root_certificate.size,
                                                             WOLFSSL_FILETYPE_ASN1);
                }
                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_CERTIFICATE_ERROR, "Unable to load root certificate");
        }

        /* Load device certificate chain */
        if (config->device_certificate_chain.buffer != NULL)
        {
                /* Check for PKCS#11 identifier */
                if (strncmp((char const*) config->device_certificate_chain.buffer,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        char label_buffer[128];
                        strncpy(label_buffer,
                                (char const*) config->device_certificate_chain.buffer +
                                        PKCS11_LABEL_IDENTIFIER_LEN,
                                sizeof(label_buffer) - 1);
                        char* label = strtok(label_buffer, PKCS11_LABEL_TERMINATOR);

                        ret = use_pkcs11_certificate_chain(endpoint, config, label);
                }
                /* Check if we have a PEM or DER file */
                else if (memcmp(config->device_certificate_chain.buffer, "-----", 5) == 0)
                {
                        /* PEM file */
                        ret = wolfSSL_CTX_use_certificate_chain_buffer_format(endpoint->wolfssl_context,
                                                                              config->device_certificate_chain
                                                                                      .buffer,
                                                                              config->device_certificate_chain
                                                                                      .size,
                                                                              WOLFSSL_FILETYPE_PEM);
                }
                else
                {
                        /* DER file */
                        ret = wolfSSL_CTX_use_certificate_chain_buffer_format(endpoint->wolfssl_context,
                                                                              config->device_certificate_chain
                                                                                      .buffer,
                                                                              config->device_certificate_chain
                                                                                      .size,
                                                                              WOLFSSL_FILETYPE_ASN1);
                }

                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_CERTIFICATE_ERROR, "Unable to load device certificate chain");
        }

        /* Load the private key */
        bool privateKeyLoaded = false;
        if (config->private_key.buffer != NULL)
        {
                /* Check for PKCS#11 identifier */
                if (strncmp((char const*) config->private_key.buffer,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        char label_buffer[128];
                        strncpy(label_buffer,
                                (char const*) config->private_key.buffer + PKCS11_LABEL_IDENTIFIER_LEN,
                                sizeof(label_buffer) - 1);
                        char* label = strtok(label_buffer, PKCS11_LABEL_TERMINATOR);

                        ret = use_pkcs11_private_key(endpoint, config, label);

#ifdef WOLFSSL_DUAL_ALG_CERTS
                        /* Check if an alternative key label is also present */
                        label = strtok(NULL, PKCS11_LABEL_TERMINATOR);
                        if ((label != NULL) &&
                            (strncmp(label, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN) == 0))
                        {
                                label += PKCS11_LABEL_IDENTIFIER_LEN;

                                if (wolfssl_check_for_error(ret))
                                        ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to load private key");

                                ret = use_pkcs11_alt_private_key(endpoint, config, label);
                        }
#endif
                }
                /* Load the private key from the buffer */
                else if (memcmp(config->private_key.buffer, "-----", 5) == 0)
                {
                        /* PEM file */
                        ret = wolfSSL_CTX_use_PrivateKey_buffer(endpoint->wolfssl_context,
                                                                config->private_key.buffer,
                                                                config->private_key.size,
                                                                WOLFSSL_FILETYPE_PEM);
                }
                else
                {
                        /* DER file */
                        ret = wolfSSL_CTX_use_PrivateKey_buffer(endpoint->wolfssl_context,
                                                                config->private_key.buffer,
                                                                config->private_key.size,
                                                                WOLFSSL_FILETYPE_ASN1);
                }

                privateKeyLoaded = true;

                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to load private key");
        }

#ifdef WOLFSSL_DUAL_ALG_CERTS
        /* Load the alternative private key */
        if (config->private_key.additional_key_buffer != NULL)
        {
                /* Check for PKCS#11 identifier */
                if (strncmp((char const*) config->private_key.additional_key_buffer,
                            PKCS11_LABEL_IDENTIFIER,
                            PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        char label_buffer[128];
                        strncpy(label_buffer,
                                (char const*) config->private_key.additional_key_buffer +
                                        PKCS11_LABEL_IDENTIFIER_LEN,
                                sizeof(label_buffer) - 1);
                        char* label = strtok(label_buffer, PKCS11_LABEL_TERMINATOR);

                        ret = use_pkcs11_alt_private_key(endpoint, config, label);
                }
                /* Load the alternative private key from the buffer */
                else if (memcmp(config->private_key.additional_key_buffer, "-----", 5) == 0)
                {
                        /* PEM file */
                        ret = wolfSSL_CTX_use_AltPrivateKey_buffer(endpoint->wolfssl_context,
                                                                   config->private_key.additional_key_buffer,
                                                                   config->private_key.additional_key_size,
                                                                   WOLFSSL_FILETYPE_PEM);
                }
                else
                {
                        /* DER file */
                        ret = wolfSSL_CTX_use_AltPrivateKey_buffer(endpoint->wolfssl_context,
                                                                   config->private_key.additional_key_buffer,
                                                                   config->private_key.additional_key_size,
                                                                   WOLFSSL_FILETYPE_ASN1);
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
                        ERROR_OUT(ASL_INTERNAL_ERROR,
                                  "Private key and device certificate do not match");
        }
#endif

        /* Set the IO callbacks for send and receive */
#if defined(WOLFSSL_USER_IO)
        wolfSSL_CTX_SetIORecv(endpoint->wolfssl_context, wolfssl_read_callback);
        wolfSSL_CTX_SetIOSend(endpoint->wolfssl_context, wolfssl_write_callback);
#endif

        /* Configure peer authentification */
        int verify_mode = WOLFSSL_VERIFY_NONE;

        if (config->psk.enable_psk == true)
        {
                /* When we have a PSK for the endpoint, we require its usage. Hence,
                 * we fail if no PSK is negotiated during the handshake. */
                verify_mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PSK;
        }

        if (config->mutual_authentication == true)
        {
                /* Enable peer authentication via certificates */
                verify_mode |= WOLFSSL_VERIFY_PEER;

                if (config->psk.enable_psk == true && config->psk.enable_cert_auth == false)
                        verify_mode |= WOLFSSL_VERIFY_FAIL_EXCEPT_PSK;
                else
                        verify_mode |= WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT;
        }
        wolfSSL_CTX_set_verify(endpoint->wolfssl_context, verify_mode, NULL);

        /* PSK config */
        if (config->psk.enable_psk)
        {
                ret = psk_setup_general(endpoint, config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT(ret, "Failed to setup PSK");
        }

        /* Configure the available cipher suites */
        char const* ciphersuites = config->ciphersuites;
        if (ciphersuites == NULL)
                ciphersuites = "TLS13-AES256-GCM-SHA384:TLS13-SHA384-SHA384";

        /* Allocate new string for the ciphersuites */
        size_t ciphersuite_len = strlen(ciphersuites) + 1;
        endpoint->ciphersuites = (char*) malloc(ciphersuite_len);
        if (endpoint->ciphersuites == NULL)
                ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for ciphersuites");
        memcpy(endpoint->ciphersuites, ciphersuites, ciphersuite_len);

        ret = wolfSSL_CTX_set_cipher_list(endpoint->wolfssl_context, endpoint->ciphersuites);
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure cipher suites");

        if (config->server_name != NULL)
        {
#if defined(HAVE_SNI)

                ret = wolfSSL_CTX_UseSNI(endpoint->wolfssl_context,
                                         WOLFSSL_SNI_HOST_NAME,
                                         config->server_name,
                                         strlen(config->server_name));
                if (wolfssl_check_for_error(ret))
                        ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure SNI hostname");
#else
                asl_log(ASL_LOG_LEVEL_DBG,
                        "SNI is not supported by the WolfSSL build, server name will be ignored");

#endif
        }

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

        TRACK_WOLFSS_HEAP_USAGE_START();

        /* Create the TLS server context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_server_method_ex(NULL), NULL);
        if (new_endpoint->wolfssl_context == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL server context");

        /* Configure the new endpoint */
        ret = configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure new TLS server context");

        /* Set wolSSL pre-shared key callbacks, if enable_psk flag is set. */
        if (config->psk.enable_psk)
        {
                ret = psk_setup_server(new_endpoint, config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT(ret, "Failed to setup PSK");
        }

        /* Configure the available curves for Key Exchange. For the server, all are allowed
         * to support various clients. */
        int wolfssl_key_exchange_curves[] = {
                WOLFSSL_SECP521R1MLKEM1024,
                WOLFSSL_ML_KEM_1024,
                WOLFSSL_ECC_SECP521R1,

                WOLFSSL_SECP384R1MLKEM1024,
                WOLFSSL_X448MLKEM768,
                WOLFSSL_SECP384R1MLKEM768,
                WOLFSSL_X25519MLKEM768,
                WOLFSSL_ML_KEM_768,
                WOLFSSL_ECC_X448,
                WOLFSSL_ECC_SECP384R1,

                WOLFSSL_SECP256R1MLKEM768,
                WOLFSSL_X25519MLKEM512,
                WOLFSSL_SECP256R1MLKEM512,
                WOLFSSL_ML_KEM_512,
                WOLFSSL_ECC_X25519,
                WOLFSSL_ECC_SECP256R1,
        };
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context,
                                     wolfssl_key_exchange_curves,
                                     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure key exchange curves");

        TRACK_WOLFSS_HEAP_USAGE_END();

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

        TRACK_WOLFSS_HEAP_USAGE_START();

        /* Create the TLS client context */
        new_endpoint->wolfssl_context = wolfSSL_CTX_new_ex(wolfTLS_client_method_ex(NULL), NULL);
        if (new_endpoint->wolfssl_context == NULL)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Unable to create a new WolfSSL client context");

        /* Configure the new endpoint */
        ret = configure_endpoint(new_endpoint, config);
        if (ret != ASL_SUCCESS)
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure new TLS client context");

        /* Set wolSSL pre-shared key callbacks, if enable_psk flag is set. */
        if (config->psk.enable_psk)
        {
                ret = psk_setup_client(new_endpoint, config);
                if (ret != ASL_SUCCESS)
                        ERROR_OUT(ret, "Failed to setup PSK");
        }

        /* Configure the curve for Key Exchange. For the client, we the first one in the
         * list is the one selected for the initial KeyShare in the ClientHello message. In
         * case the server doesn't support this curve, a HelloRetryRequest is generated with
         * a curve from the supported_groups extension (this list contains all curves from
         * the list below). */
        int wolfssl_key_exchange_curves[] = {
                WOLFSSL_SECP384R1MLKEM768, // Default

                WOLFSSL_SECP521R1MLKEM1024,
                WOLFSSL_ML_KEM_1024,
                WOLFSSL_ECC_SECP521R1,

                WOLFSSL_SECP384R1MLKEM1024,
                WOLFSSL_X448MLKEM768,
                WOLFSSL_SECP384R1MLKEM768,
                WOLFSSL_X25519MLKEM768,
                WOLFSSL_ML_KEM_768,
                WOLFSSL_ECC_X448,
                WOLFSSL_ECC_SECP384R1,

                WOLFSSL_SECP256R1MLKEM768,
                WOLFSSL_X25519MLKEM512,
                WOLFSSL_SECP256R1MLKEM512,
                WOLFSSL_ML_KEM_512,
                WOLFSSL_ECC_X25519,
                WOLFSSL_ECC_SECP256R1,
        };
        if (config->key_exchange_method != ASL_KEX_DEFAULT)
        {
                switch (config->key_exchange_method)
                {
                case ASL_KEX_CLASSIC_SECP256:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ECC_SECP256R1;
                        break;
                case ASL_KEX_CLASSIC_SECP384:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ECC_SECP384R1;
                        break;
                case ASL_KEX_CLASSIC_SECP521:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ECC_SECP521R1;
                        break;
                case ASL_KEX_CLASSIC_X25519:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ECC_X25519;
                        break;
                case ASL_KEX_CLASSIC_X448:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ECC_X448;
                        break;
                case ASL_KEX_PQC_MLKEM512:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ML_KEM_512;
                        break;
                case ASL_KEX_PQC_MLKEM768:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ML_KEM_768;
                        break;
                case ASL_KEX_PQC_MLKEM1024:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_ML_KEM_1024;
                        break;
                case ASL_KEX_HYBRID_SECP256_MLKEM512:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_SECP256R1MLKEM512;
                        break;
                case ASL_KEX_HYBRID_SECP256_MLKEM768:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_SECP256R1MLKEM768;
                        break;
                case ASL_KEX_HYBRID_SECP521_MLKEM1024:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_SECP521R1MLKEM1024;
                        break;
                case ASL_KEX_HYBRID_SECP384_MLKEM1024:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_SECP384R1MLKEM1024;
                        break;
                case ASL_KEX_HYBRID_X25519_MLKEM512:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_X25519MLKEM512;
                        break;
                case ASL_KEX_HYBRID_X448_MLKEM768:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_X448MLKEM768;
                        break;
                case ASL_KEX_HYBRID_X25519_MLKEM768:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_X25519MLKEM768;
                        break;
                case ASL_KEX_HYBRID_SECP384_MLKEM768: /* Order change for default! */
                default:
                        wolfssl_key_exchange_curves[0] = WOLFSSL_SECP384R1MLKEM768;
                        break;
                }
        }
        ret = wolfSSL_CTX_set_groups(new_endpoint->wolfssl_context,
                                     wolfssl_key_exchange_curves,
                                     sizeof(wolfssl_key_exchange_curves) / sizeof(int));
        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to configure key exchange curve");

        TRACK_WOLFSS_HEAP_USAGE_END();

        return new_endpoint;

cleanup:
        asl_free_endpoint(new_endpoint);

        return NULL;
}

/* Free ressources of an endpoint. */
void asl_free_endpoint(asl_endpoint* endpoint)
{
        if (endpoint != NULL)
        {
                TRACK_WOLFSS_HEAP_USAGE_START();

                /* Properly cleanup PKCS#11 stuff */
                pkcs11_endpoint_cleanup(endpoint);

                /* Free the WolfSSL context */
                if (endpoint->wolfssl_context != NULL)
                        wolfSSL_CTX_free(endpoint->wolfssl_context);

                /* Free the PSK stuff */
                psk_endpoint_cleanup(endpoint);

#if defined(HAVE_SECRET_CALLBACK)
                if (endpoint->keylog_file != NULL)
                        free(endpoint->keylog_file);
#endif

                if (endpoint->ciphersuites != NULL)
                        free(endpoint->ciphersuites);

                free(endpoint);

                TRACK_WOLFSS_HEAP_USAGE_END();
        }
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

#endif

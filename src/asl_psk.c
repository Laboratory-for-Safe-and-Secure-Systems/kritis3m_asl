
#include <errno.h>
#include <stdlib.h>

#include "asl_logging.h"
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

#ifndef NO_PSK

/* Internal WolfSSL PSK client callback */
static unsigned int wolfssl_tls13_client_cb(WOLFSSL* ssl,
                                            const char* hint,
                                            char* identity,
                                            unsigned int id_max_len,
                                            unsigned char* key,
                                            unsigned int key_max_len,
                                            const char** ciphersuite)
{
        (void) hint;
        (void) id_max_len;
        (void) ciphersuite;

        // int Base64_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);

        unsigned int key_len = 0;

        asl_session* session = (asl_session*) wolfSSL_get_psk_callback_ctx(ssl);
        if (session != NULL)
        {
                if (session->endpoint->psk.psk_client_cb != NULL)
                {
                        /* Call external callback to get key and identity */
                        key_len = session->endpoint->psk.psk_client_cb(key, identity);
                }
                else if (session->endpoint->psk.master_key != NULL)
                {
                        /* Use the master key as PSK key */
                        key_len = (unsigned int) strlen(session->endpoint->psk.master_key);
                        if (key_len > key_max_len)
                                key_len = key_max_len;
                        memcpy(key, session->endpoint->psk.master_key, key_len);

                        strcpy(identity, "default_identity");
                }
                else
                {
                        asl_log(ASL_LOG_LEVEL_ERR, "ASL PSK client callback not set!");
                }

                *ciphersuite = session->endpoint->ciphersuites;
        }
        else
        {
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set!");
        }

        return key_len;
}

/* Internal WolfSSL PSK server callback */
static unsigned int wolfssl_tls13_server_cb(WOLFSSL* ssl,
                                            const char* identity,
                                            unsigned char* key,
                                            unsigned int key_max_len,
                                            const char** ciphersuite)
{
        (void) key_max_len;

        unsigned int key_len = 0;

        asl_session* session = (asl_session*) wolfSSL_get_psk_callback_ctx(ssl);
        if (session != NULL)
        {
                if (session->endpoint->psk.psk_server_cb != NULL)
                {
                        /* Call external callback to get key for identity */
                        key_len = session->endpoint->psk.psk_server_cb(key, identity, ciphersuite);
                }
                else if (session->endpoint->psk.master_key != NULL)
                {
                        /* Use the master key as PSK key */
                        key_len = (unsigned int) strlen(session->endpoint->psk.master_key);
                        if (key_len > key_max_len)
                                key_len = key_max_len;
                        memcpy(key, session->endpoint->psk.master_key, key_len);
                }
                else
                {
                        asl_log(ASL_LOG_LEVEL_ERR, "ASL PSK server callback not set!");
                }

                *ciphersuite = session->endpoint->ciphersuites;
        }
        else
        {
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set!");
        }

        return key_len;
}
#endif /* NO_PSK */

int psk_setup_general(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
#ifndef NO_PSK
        int ret = 0;

        /* Only allow PSK together with an ephemeral key exchange */
        wolfSSL_CTX_only_dhe_psk(endpoint->wolfssl_context);

        if (config->psk.master_key != NULL)
        {
                endpoint->psk.master_key = (char*) malloc(strlen(config->psk.master_key) + 1);
                if (endpoint->psk.master_key == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for PSK master key");

                strcpy(endpoint->psk.master_key, config->psk.master_key);
        }
        else if (config->psk.use_external_callbacks == false)
        {
                ERROR_OUT(ASL_ARGUMENT_ERROR,
                          "Either a PSK master key or external callbacks must be used");
        }
        else
                endpoint->psk.master_key = NULL;

cleanup:
        return ret;
#else
        (void) endpoint;
        (void) config;

        asl_log(ASL_LOG_LEVEL_ERR,
                "PSK support is not compiled in, please compile with support enabled");
        return ASL_PSK_ERROR;
#endif
}

int psk_setup_server(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
#ifndef NO_PSK
        int ret = 0;

        /* Set wolfSSL internal PSK callback (not passed to the user) */
        wolfSSL_CTX_set_psk_server_tls13_callback(endpoint->wolfssl_context, wolfssl_tls13_server_cb);

        if (wolfSSL_CTX_use_psk_identity_hint(endpoint->wolfssl_context, "asl server") != WOLFSSL_SUCCESS)
        {
                ERROR_OUT(ASL_INTERNAL_ERROR, "Failed to set psk identity hint");
        }

        /* Set asl callback, to reference user implementation */
        if (config->psk.use_external_callbacks && config->psk.psk_server_cb != NULL)
                endpoint->psk.psk_server_cb = config->psk.psk_server_cb;
        else
                endpoint->psk.psk_server_cb = NULL;

        /* To avoid ambiguity, we set the PSK client callback here to NULL */
        endpoint->psk.psk_client_cb = NULL;

cleanup:
        return ret;
#else
        (void) endpoint;
        (void) config;

        asl_log(ASL_LOG_LEVEL_ERR,
                "PSK support is not compiled in, please compile with support enabled");
        return ASL_PSK_ERROR;
#endif
}

int psk_setup_client(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
#ifndef NO_PSK
        int ret = 0;

        /* Set wolfSSL internal PSK callback (not passed to the user) */
        wolfSSL_CTX_set_psk_client_tls13_callback(endpoint->wolfssl_context, wolfssl_tls13_client_cb);

        /* Set asl callback, to reference user implementation */
        if (config->psk.use_external_callbacks && config->psk.psk_client_cb != NULL)
                endpoint->psk.psk_client_cb = config->psk.psk_client_cb;
        else
                endpoint->psk.psk_client_cb = NULL;

        /* To avoid ambiguity, we set the PSK server callback here to NULL */
        endpoint->psk.psk_server_cb = NULL;

cleanup:
        return ret;
#else
        (void) endpoint;
        (void) config;

        asl_log(ASL_LOG_LEVEL_ERR,
                "PSK support is not compiled in, please compile with support enabled");
        return ASL_PSK_ERROR;
#endif
}

void psk_endpoint_cleanup(asl_endpoint* endpoint)
{
#ifndef NO_PSK
        if (endpoint->psk.master_key != NULL)
        {
                free(endpoint->psk.master_key);
                endpoint->psk.master_key = NULL;
        }
#endif
}

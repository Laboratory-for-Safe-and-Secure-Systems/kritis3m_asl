
#include <errno.h>
#include <stdlib.h>

#include "asl_logging.h"
#include "asl_psk.h"
#include "asl_types.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/coding.h"
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

static int handle_external_callback_client(asl_session* session,
                                           char* identity,
                                           uint32_t id_max_len,
                                           uint8_t* key,
                                           uint32_t key_max_len)
{
        int ret = 0;
        char key_base64[128] = {0};
        char identity_ext[128] = {0};

        /* Execute the user callback */
        ret = session->endpoint->psk.psk_client_cb(key_base64,
                                                   identity_ext,
                                                   session->endpoint->psk.callback_ctx);

        if (ret <= 0)
                ERROR_OUT(-1, "PSK client callback failed");

        int id_len = strlen(identity_ext);
        word32 key_len = strlen(key_base64);

        if (id_len > id_max_len || key_len > key_max_len)
                ERROR_OUT(-1, "PSK client callback returned oversized data");

        key_len = key_max_len;

        /* As the key is base64 encoded, decode it. */
        ret = Base64_Decode((byte*) key_base64, key_len, key, &key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

        /* Copy the identity */
        strncpy(identity, identity_ext, id_max_len);

        ret = key_len;

cleanup:
        return ret;
}

static int handle_external_callback_server(asl_session* session,
                                           char const* identity,
                                           uint8_t* key,
                                           uint32_t key_max_len)
{
        int ret = 0;
        char key_base64[128] = {0};

        /* Execute the user callback */
        ret = session->endpoint->psk.psk_server_cb(key_base64,
                                                   identity,
                                                   session->endpoint->psk.callback_ctx);

        if (ret <= 0)
                ERROR_OUT(-1, "PSK server callback failed");

        word32 key_len = strlen(key_base64);

        if (key_len > key_max_len)
                ERROR_OUT(-1, "PSK server callback returned oversized data");

        key_len = key_max_len;

        /* As the key is base64 encoded, decode it. */
        ret = Base64_Decode((byte*) key_base64, key_len, key, &key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

        ret = key_len;

cleanup:
        return ret;
}

static int handle_local_master_key_client(asl_session* session,
                                          char* identity,
                                          uint32_t id_max_len,
                                          uint8_t* key,
                                          uint32_t key_max_len)
{
        int ret = 0;
        uint8_t identity_raw[128] = {0};

        word32 key_len = key_max_len;
        word32 id_len = id_max_len;

        /* Decode the master key */
        ret = Base64_Decode((byte*) session->endpoint->psk.master_key,
                            strlen(session->endpoint->psk.master_key),
                            key,
                            &key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

        /* Generate random data */
        ret = wc_RNG_GenerateBlock(wolfSSL_GetRNG(session->wolfssl_session), identity_raw, key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to generate random data: %d", ret);

        /* Derive PSK from master key and random data */
        for (uint32_t i = 0; i < key_len; i++)
                key[i] ^= identity_raw[i];

        /* Encode the identity */
        ret = Base64_Encode_NoNl(identity_raw, key_len, identity, &id_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to encode PSK identity: %d", ret);

        ret = key_len;

cleanup:
        return ret;
}

static int handle_local_master_key_server(asl_session* session,
                                          char const* identity,
                                          uint8_t* key,
                                          uint32_t key_max_len)
{
        int ret = 0;
        uint8_t identity_raw[128] = {0};

        word32 key_len = key_max_len;
        word32 id_len = sizeof(identity_raw);

        /* Decode the master key */
        ret = Base64_Decode((byte*) session->endpoint->psk.master_key,
                            strlen(session->endpoint->psk.master_key),
                            key,
                            &key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

        /* Decode the received identity */
        ret = Base64_Decode((byte*) identity, strlen(identity), identity_raw, &id_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK identity: %d", ret);

        if (id_len != key_len)
                ERROR_OUT(-1, "Identity and key length mismatch");

        /* Derive the PSK key from the master key and the identity */
        for (uint32_t i = 0; i < key_len; i++)
                key[i] ^= identity_raw[i];

        ret = key_len;

cleanup:

        return ret;
}

static int handle_pkcs11_master_key_client(asl_session* session,
                                           char* identity,
                                           uint32_t id_max_len,
                                           uint8_t* key,
                                           uint32_t key_max_len)
{
        int ret = 0;

        return ret;
}

static int handle_pkcs11_master_key_server(asl_session* session,
                                           char const* identity,
                                           uint8_t* key,
                                           uint32_t key_max_len)
{
        int ret = 0;

        return ret;
}

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

        unsigned int key_len = 0;

        asl_session* session = (asl_session*) wolfSSL_get_psk_callback_ctx(ssl);
        if (session != NULL && session->endpoint != NULL)
        {
                if (session->endpoint->psk.use_external_callbacks == true &&
                    session->endpoint->psk.psk_client_cb != NULL)
                {
                        key_len = handle_external_callback_client(session,
                                                                  identity,
                                                                  id_max_len,
                                                                  key,
                                                                  key_max_len);
                }
                else if (session->endpoint->psk.master_key != NULL &&
                         strncmp((char const*) session->endpoint->psk.master_key,
                                 PKCS11_LABEL_IDENTIFIER,
                                 PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        key_len = handle_pkcs11_master_key_client(session,
                                                                  identity,
                                                                  id_max_len,
                                                                  key,
                                                                  key_max_len);
                }
                else if (session->endpoint->psk.master_key != NULL)
                {
                        key_len = handle_local_master_key_client(session,
                                                                 identity,
                                                                 id_max_len,
                                                                 key,
                                                                 key_max_len);
                }

                if (key_len > 0)
                        *ciphersuite = session->endpoint->ciphersuites;
                else
                        asl_log(ASL_LOG_LEVEL_ERR, "Unable to get client-side PSK");
        }
        else
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set");

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
        if (session != NULL && session->endpoint != NULL)
        {
                if (session->endpoint->psk.use_external_callbacks == true &&
                    session->endpoint->psk.psk_server_cb != NULL)
                {
                        key_len = handle_external_callback_server(session, identity, key, key_max_len);
                }
                else if (session->endpoint->psk.master_key != NULL &&
                         strncmp((char const*) session->endpoint->psk.master_key,
                                 PKCS11_LABEL_IDENTIFIER,
                                 PKCS11_LABEL_IDENTIFIER_LEN) == 0)
                {
                        key_len = handle_pkcs11_master_key_server(session, identity, key, key_max_len);
                }
                else if (session->endpoint->psk.master_key != NULL)
                {
                        key_len = handle_local_master_key_server(session, identity, key, key_max_len);
                }

                if (key_len > 0)
                        *ciphersuite = session->endpoint->ciphersuites;
                else
                        asl_log(ASL_LOG_LEVEL_ERR, "Unable to get server-side PSK");
        }
        else
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set");

        return key_len;
}
#endif /* NO_PSK */

int psk_setup_general(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
#ifndef NO_PSK
        int ret = 0;

        /* Only allow PSK together with an ephemeral key exchange */
        wolfSSL_CTX_only_dhe_psk(endpoint->wolfssl_context);

        endpoint->psk.use_external_callbacks = false;

        if (config->psk.master_key != NULL)
        {
                endpoint->psk.master_key = (char*) malloc(strlen(config->psk.master_key) + 1);
                if (endpoint->psk.master_key == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for PSK master key");

                strcpy(endpoint->psk.master_key, config->psk.master_key);
        }
        else if (config->psk.use_external_callbacks == true)
        {
                endpoint->psk.master_key = NULL;
                endpoint->psk.use_external_callbacks = true;
                endpoint->psk.callback_ctx = config->psk.callback_ctx;
        }
        else
                ERROR_OUT(ASL_ARGUMENT_ERROR,
                          "Either a PSK master key or external callbacks must be used");

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


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
#include "wolfssl/wolfcrypt/hmac.h"
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
        ret = session->endpoint->psk.psk_client_cb(key_base64, identity_ext, session->endpoint->psk.key);

        if (ret <= 0)
                ERROR_OUT(-1, "PSK client callback failed");

        int id_ext_len = strlen(identity_ext);
        word32 key_len = strlen(key_base64);

        /* Check sizes. We append the received external identity string to our existing
         * identity, separated by a colon (Hence the 2 additional chars) */
        if (((id_ext_len + strlen(session->endpoint->psk.identity) + 2) > id_max_len) ||
            (key_len > key_max_len))
                ERROR_OUT(-1, "PSK client callback returned oversized data");

        key_len = key_max_len;

        /* As the key is base64 encoded, decode it. */
        ret = Base64_Decode((byte*) key_base64, key_len, key, &key_len);
        if (ret != 0)
                ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

        /* Copy the identity */
        snprintf(identity, id_max_len, "%s:%s", session->endpoint->psk.identity, identity_ext);

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

        /* Remove the identity prefix */
        char const* identity_ext = strchr(identity, ':');
        if (identity_ext == NULL)
                ERROR_OUT(-1, "Invalid external identity");
        identity_ext += 1; /* Skip the colon */

        /* Execute the user callback */
        ret = session->endpoint->psk.psk_server_cb(key_base64, identity_ext, session->endpoint->psk.key);

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

static int handle_local_key_client(asl_session* session,
                                   char* identity,
                                   uint32_t id_max_len,
                                   uint8_t* key,
                                   uint32_t key_max_len)
{
        int ret = 0;
        int key_len;
        int id_len = strlen(session->endpoint->psk.identity);

        if (id_len > id_max_len - 1)
                ERROR_OUT(-1, "PSK identity too long");

        /* Copy the identifier */
        memcpy(identity, session->endpoint->psk.identity, id_len + 1); /* Copy including terminator */

        /* Check if we have an external PSK. Only check if the key is equal to the
         * PKCS11_LABEL_IDENTIFIER excluding the colon at the end. */
        if (memcmp(session->endpoint->psk.key,
                   PKCS11_LABEL_IDENTIFIER,
                   PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
        {
                /* Use the identifier as the PKCS#11 label */
                ret = wolfSSL_use_psk_key_label(session->wolfssl_session,
                                                session->endpoint->psk.identity,
                                                session->endpoint->pkcs11_module.device_id);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to use PSK key label: %d", ret);

                key_len = id_len + 1; /* Including terminator */
                memcpy(key, session->endpoint->psk.identity, key_len);
        }
        else
        {
                /* Copy key */
                key_len = session->endpoint->psk.key_len;
                memcpy(key, session->endpoint->psk.key, key_len);
        }

        ret = key_len;

cleanup:
        return ret;
}

static int handle_local_key_server(asl_session* session,
                                   char const* identity,
                                   uint8_t* key,
                                   uint32_t key_max_len)
{
        int ret = 0;
        int key_len;
        int id_len = strlen(session->endpoint->psk.identity);

        /* We already checked that the received identity is equal to our own one. */
        (void) identity;

        /* Check if we have an external PSK. Only check if the key is equal to the
         * PKCS11_LABEL_IDENTIFIER excluding the colon at the end. */
        if (memcmp(session->endpoint->psk.key,
                   PKCS11_LABEL_IDENTIFIER,
                   PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
        {
                /* Use the identifier as the PKCS#11 label */
                ret = wolfSSL_use_psk_key_label(session->wolfssl_session,
                                                session->endpoint->psk.identity,
                                                session->endpoint->pkcs11_module.device_id);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to use PSK key label: %d", ret);

                key_len = id_len + 1; /* Including terminator */
                memcpy(key, session->endpoint->psk.identity, key_len);
        }
        else
        {
                /* Copy key */
                key_len = session->endpoint->psk.key_len;
                memcpy(key, session->endpoint->psk.key, key_len);
        }

        ret = key_len;

cleanup:

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
                else if (session->endpoint->psk.key != NULL)
                {
                        key_len = handle_local_key_client(session, identity, id_max_len, key, key_max_len);
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
                /* Check if the received identity matches ours. */
                if (strncmp(identity,
                            session->endpoint->psk.identity,
                            strlen(session->endpoint->psk.identity)) != 0)
                        return 0;

                /* Check if we have a local PSK or if we have to use the external interface. */
                if (session->endpoint->psk.use_external_callbacks == true &&
                    session->endpoint->psk.psk_server_cb != NULL)
                {
                        key_len = handle_external_callback_server(session, identity, key, key_max_len);
                }
                else if (session->endpoint->psk.key != NULL)
                {
                        key_len = handle_local_key_server(session, identity, key, key_max_len);
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
        uint8_t key_raw[128] = {0};
        word32 key_len = sizeof(key_raw);

        /* Only allow PSK together with an ephemeral key exchange */
        wolfSSL_CTX_only_dhe_psk(endpoint->wolfssl_context);

        if (config->psk.key != NULL)
        {
                /* Check if a Base64 decoded key is given or a PKCS#11 one is referenced. */
                if (memcmp(config->psk.key, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN - 1) ==
                    0)
                {
                        memcpy(key_raw, config->psk.key, PKCS11_LABEL_IDENTIFIER_LEN - 1);
                        key_raw[PKCS11_LABEL_IDENTIFIER_LEN - 1] = '\0';
                        key_len = PKCS11_LABEL_IDENTIFIER_LEN;
                }
                else
                {
                        /* Base64 decode the given key */
                        ret = Base64_Decode((byte const*) config->psk.key,
                                            strlen(config->psk.key),
                                            key_raw,
                                            &key_len);
                        if (ret != 0)
                                ERROR_OUT(ASL_PSK_ERROR, "Failed to decode PSK key: %d", ret);
                }

                /* Store decoded key */
                endpoint->psk.key_len = key_len;
                endpoint->psk.key = malloc(key_len);
                if (endpoint->psk.key == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for PSK master key");

                memcpy(endpoint->psk.key, key_raw, key_len);
        }
        else if (config->psk.use_external_callbacks == true)
        {
                endpoint->psk.use_external_callbacks = true;
                endpoint->psk.key = config->psk.callback_ctx;
        }
        else
                ERROR_OUT(ASL_ARGUMENT_ERROR, "Either a PSK key or external callbacks must be used");

        /* Store the identity */
        if (config->psk.identity != NULL)
        {
                size_t id_len = strlen(config->psk.identity) + 1;
                endpoint->psk.identity = malloc(id_len);
                if (endpoint->psk.identity == NULL)
                        ERROR_OUT(ASL_MEMORY_ERROR, "Unable to allocate memory for PSK identity");
                memcpy(endpoint->psk.identity, config->psk.identity, id_len);
        }
        else
                ERROR_OUT(ASL_ARGUMENT_ERROR, "PSK identity must be set");

#ifdef WOLFSSL_CERT_WITH_EXTERN_PSK
        /* If configured in the WOLFSSL usersettings, we can activate the extension for certificates
         * in addition to the PSKs. */
        endpoint->psk.enable_cert_auth = config->psk.enable_cert_auth;
        ret = wolfSSL_CTX_set_cert_with_extern_psk(endpoint->wolfssl_context,
                                                   (int) config->psk.enable_cert_auth);
        if (ret != WOLFSSL_SUCCESS)
                goto cleanup;
#endif

        return ASL_SUCCESS;

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
        if (endpoint->psk.use_external_callbacks == false && endpoint->psk.key != NULL)
        {
                free(endpoint->psk.key);
                endpoint->psk.key = NULL;
        }
        if (endpoint->psk.identity != NULL)
        {
                free(endpoint->psk.identity);
                endpoint->psk.identity = NULL;
        }
#endif
}


#include <errno.h>
#include <stdlib.h>

#include "asl_logging.h"
#include "asl_pkcs11.h"
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
                                           word32 id_max_len,
                                           uint8_t* context,
                                           word32* ctx_len,
                                           uint8_t* key,
                                           word32* key_len)
{
        int ret = 0;
        int id_ext_len = 0;

        /* identity and context may be NULL, indicating that only the PSK is necessary */

        /* Check if we have to execute the external callback. This ensures that the external
         * callback is only called once, no matter how often these internal ones are called.
         */
        if ((session->external_psk.identity == NULL) || (session->external_psk.key == NULL))
        {
                char key_base64[64] = {0};
                char identity_ext[MAX_PSK_CTX_LEN] = {0};

                /* Execute the user callback */
                ret = session->endpoint->psk.psk_client_cb(key_base64,
                                                           identity_ext,
                                                           session->endpoint->psk.key);

                if (ret <= 0)
                        ERROR_OUT(-1, "PSK client callback failed");

                id_ext_len = strlen(identity_ext);
                word32 key_ext_len = strlen(key_base64);
                if (key_ext_len != ret)
                        ERROR_OUT(-1, "PSK client callback returned invalid data");

                /* Copy identity into a newly allocated buffer */
                session->external_psk.identity = (char*) malloc(id_ext_len + 1);
                if (session->external_psk.identity == NULL)
                        ERROR_OUT(-1, "Failed to allocate memory for external identity");
                memcpy(session->external_psk.identity, identity_ext, id_ext_len + 1);

                /* Base64 decoded the received key. Store the result directly in the
                 * provided buffer of WolfSSL. */
                ret = Base64_Decode((byte*) key_base64, key_ext_len, key, key_len);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

                /* Copy the decoded PSK into a newly allocated buffer for later use
                 * (as this callback is called multiple times). */
                session->external_psk.key = (void*) malloc(*key_len);
                if (session->external_psk.key == NULL)
                        ERROR_OUT(-1, "Failed to allocate memory for external key");
                memcpy(session->external_psk.key, key, *key_len);
                session->external_psk.key_len = *key_len;
        }
        else
        {
                if (session->external_psk.key_len > *key_len)
                        ERROR_OUT(-1, "Key buffer too small");

                /* We already have the external identity and PSK, simply copy it. */
                memcpy(key, session->external_psk.key, session->external_psk.key_len);
                *key_len = session->external_psk.key_len;
        }

        /* Copy our identity (including terminator) */
        if (identity != NULL)
        {
                size_t id_len_internal = strlen(session->endpoint->psk.identity) + 1;
                if (id_len_internal > id_max_len)
                        ERROR_OUT(-1, "PSK identity buffer too small");
                memcpy(identity, session->endpoint->psk.identity, id_len_internal);
        }

        /* Store the external identity as the context (without terminator, as length is
         * a separate parameter) */
        if (context != NULL && ctx_len != NULL)
        {
                id_ext_len = strlen(session->external_psk.identity);
                if (id_ext_len > *ctx_len)
                        ERROR_OUT(-1, "PSK context buffer too small");
                memcpy(context, session->external_psk.identity, id_ext_len);
                *ctx_len = id_ext_len;
        }

cleanup:
        return ret;
}

static int handle_external_callback_server(asl_session* session,
                                           char const* identity,
                                           uint8_t const* context,
                                           word32 ctx_len,
                                           uint8_t* key,
                                           word32* key_len)
{
        int ret = 0;

        /* Check if we have to execute the external callback. This ensures that the external
         * callback is only called once, no matter how often these internal ones are called.
         */
        if (session->external_psk.key == NULL)
        {
                char key_base64[64] = {0};
                char identity_ext[64] = {0};

                /* Get to the external id stored in the context */
                if (ctx_len > sizeof(identity_ext))
                        ERROR_OUT(-1, "PSK context buffer too big");

                memcpy(identity_ext, context, ctx_len);
                identity_ext[ctx_len] = '\0';

                /* Execute the user callback */
                ret = session->endpoint->psk.psk_server_cb(key_base64,
                                                           identity_ext,
                                                           session->endpoint->psk.key);
                if (ret <= 0)
                        ERROR_OUT(-1, "PSK server callback failed");

                word32 key_ext_len = strlen(key_base64);
                if (key_ext_len != ret)
                        ERROR_OUT(-1, "PSK client callback returned invalid data");

                /* Base64 decoded the received key. Store the result directly in the
                 * provided buffer of WolfSSL. */
                ret = Base64_Decode((byte*) key_base64, key_ext_len, key, key_len);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to decode PSK key: %d", ret);

                /* Copy the decoded PSK into a newly allocated buffer for later use
                 * (as this callback is called multiple times). */
                session->external_psk.key = (void*) malloc(*key_len);
                if (session->external_psk.key == NULL)
                        ERROR_OUT(-1, "Failed to allocate memory for external key");
                memcpy(session->external_psk.key, key, *key_len);
                session->external_psk.key_len = *key_len;
        }
        else
        {
                if (session->external_psk.key_len > *key_len)
                        ERROR_OUT(-1, "Key buffer too small");

                /* We already have the external PSK, simply copy it. */
                memcpy(key, session->external_psk.key, session->external_psk.key_len);
                *key_len = session->external_psk.key_len;
        }

cleanup:
        return ret;
}

static int handle_local_key_client(asl_session* session,
                                   char* identity,
                                   word32 id_max_len,
                                   uint8_t* context,
                                   word32* ctx_len,
                                   uint8_t* key,
                                   word32* key_len)
{
        int ret = 0;

        /* identity and context may be NULL, indicating that only the PSK is necessary */

        /* Copy our identity */
        if (identity != NULL)
        {
                size_t id_len_internal = strlen(session->endpoint->psk.identity);
                if (id_len_internal > id_max_len)
                        ERROR_OUT(-1, "PSK identity buffer too small");
                memcpy(identity, session->endpoint->psk.identity, id_len_internal);
        }

        /* Put 32 random byte into the context to add entropy to the imported PSK.
         * This makes sure that handshake is forward secure. */
        if (context != NULL && ctx_len != NULL)
        {
                WC_RNG rng;

                if (*ctx_len < 32)
                        ERROR_OUT(-1, "PSK context buffer too small");

                ret = wc_InitRng(&rng);
                if (ret == 0)
                {
                        ret = wc_RNG_GenerateBlock(&rng, context, 32);
                        wc_FreeRng(&rng);
                }
                if (ret == 0)
                {
                        *ctx_len = 32;
                }
                else
                        ERROR_OUT(-1, "Failed to generate random data for PSK context: %d", ret);
        }

        /* Check if we have an external PSK. Only check if the key is equal to the
         * PKCS11_LABEL_IDENTIFIER excluding the colon at the end. */
        if (memcmp(session->endpoint->psk.key,
                   PKCS11_LABEL_IDENTIFIER,
                   PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
        {
#ifdef WOLF_PRIVATE_KEY_ID
                /* Use the identifier as the PKCS#11 label */
                ret = wolfSSL_use_external_psk_label(session->wolfssl_session,
                                                     session->endpoint->psk.identity,
                                                     session->endpoint->pkcs11_module.device_id);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to use PSK key label: %d", ret);
#else
                ERROR_OUT(-1, "PKCS#11 support not enabled", ret);
#endif
        }
        else
        {
                if (session->endpoint->psk.key_len > *key_len)
                        ERROR_OUT(-1, "PSK key buffer too small");

                /* Copy key */
                *key_len = session->endpoint->psk.key_len;
                memcpy(key, session->endpoint->psk.key, *key_len);
        }

cleanup:
        return ret;
}

static int handle_local_key_server(asl_session* session,
                                   char const* identity,
                                   uint8_t const* context,
                                   uint32_t ctx_len,
                                   uint8_t* key,
                                   uint32_t* key_len)
{
        int ret = 0;

        (void) identity; /* Already checked... */
        (void) context;  /* Not used */
        (void) ctx_len;  /* Not used */

        /* Check if we have an external PSK. Only check if the key is equal to the
         * PKCS11_LABEL_IDENTIFIER excluding the colon at the end. */
        if (memcmp(session->endpoint->psk.key,
                   PKCS11_LABEL_IDENTIFIER,
                   PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
        {
#ifdef WOLF_PRIVATE_KEY_ID
                /* Use the identifier as the PKCS#11 label */
                ret = wolfSSL_use_external_psk_label(session->wolfssl_session,
                                                     session->endpoint->psk.identity,
                                                     session->endpoint->pkcs11_module.device_id);
                if (ret != 0)
                        ERROR_OUT(-1, "Failed to use PSK key label: %d", ret);
#else
                ERROR_OUT(-1, "PKCS#11 support not enabled", ret);
#endif
        }
        else
        {
                if (session->endpoint->psk.key_len > *key_len)
                        ERROR_OUT(-1, "Key buffer too small");

                /* Copy key */
                *key_len = session->endpoint->psk.key_len;
                memcpy(key, session->endpoint->psk.key, *key_len);
        }

cleanup:
        return ret;
}

/* Internal WolfSSL PSK client callback.
 * On entry, the '_len' arguments contain the maximum allowed length.
 */
static int wolfssl_tls13_client_cb(WOLFSSL* ssl,
                                   char* identity,
                                   word32 id_max_len,
                                   unsigned char* context,
                                   word32* ctx_len,
                                   unsigned char* key,
                                   word32* key_len)
{
        int ret = 0;
        asl_session* session = (asl_session*) wolfSSL_get_psk_callback_ctx(ssl);

        if (session != NULL && session->endpoint != NULL)
        {
                if (session->endpoint->psk.use_external_callbacks == true &&
                    session->endpoint->psk.psk_client_cb != NULL)
                {
                        ret = handle_external_callback_client(session,
                                                              identity,
                                                              id_max_len,
                                                              context,
                                                              ctx_len,
                                                              key,
                                                              key_len);
                }
                else if (session->endpoint->psk.key != NULL)
                {
                        ret = handle_local_key_client(session,
                                                      identity,
                                                      id_max_len,
                                                      context,
                                                      ctx_len,
                                                      key,
                                                      key_len);
                }
        }
        else
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set");

        return ret;
}

/* Internal WolfSSL PSK server callback.
 * On entry, the 'key_len' argument contains the maximum key length.
 */
static int wolfssl_tls13_server_cb(WOLFSSL* ssl,
                                   char const* identity,
                                   unsigned char const* context,
                                   word32 ctx_len,
                                   unsigned char* key,
                                   word32* key_len)
{
        int ret = 0;
        asl_session* session = (asl_session*) wolfSSL_get_psk_callback_ctx(ssl);

        if (session != NULL && session->endpoint != NULL)
        {
                /* Check if the received identity matches ours. */
                size_t our_id_len = strlen(session->endpoint->psk.identity);
                size_t id_len = strlen(identity);
                if (id_len != our_id_len)
                        return 0;
                else if (memcmp(identity, session->endpoint->psk.identity, our_id_len) != 0)
                        return 0;

                /* Check if we have a local PSK or if we have to use the external interface. */
                if (session->endpoint->psk.use_external_callbacks == true &&
                    session->endpoint->psk.psk_server_cb != NULL)
                {
                        ret = handle_external_callback_server(session, identity, context, ctx_len, key, key_len);
                }
                else if (session->endpoint->psk.key != NULL)
                {
                        ret = handle_local_key_server(session, identity, context, ctx_len, key, key_len);
                }
        }
        else
                asl_log(ASL_LOG_LEVEL_ERR, "ASL session pointer not set");

        return ret;
}
#endif /* NO_PSK */

int psk_setup_general(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
#ifndef NO_PSK
        int ret = 0;
        uint8_t key_raw[128] = {0};
        word32 key_len = sizeof(key_raw);

        /* setup PSK combination with (EC)DHE key gen. */
        if(config->psk.enable_dhe_psk)
        {
                /* PSK + (EC)DHE */
                wolfSSL_CTX_only_dhe_psk(endpoint->wolfssl_context);
        }
        else
        {
                /* PSK only */
                wolfSSL_CTX_no_dhe_psk(endpoint->wolfssl_context);
        }

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

        /* Check if we use a PKCS#11 based PSK. In this case, we have to initialize the token */
        if (memcmp(endpoint->psk.key, PKCS11_LABEL_IDENTIFIER, PKCS11_LABEL_IDENTIFIER_LEN - 1) == 0)
        {
#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
                /* Initialize the PKCS#11 module */
                ret = configure_pkcs11_endpoint(endpoint, config);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure PKCS#11 crypto module");

                asl_log(ASL_LOG_LEVEL_DBG, "Using external PSK with label \"%s\"", endpoint->psk.identity);
#else
                ERROR_OUT(ASL_PKCS11_ERROR, "PKCS#11 support is not compiled in, please compile with support enabled");
#endif
        }

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
        wolfSSL_CTX_set_psk_server_importer_callback(endpoint->wolfssl_context,
                                                     wolfssl_tls13_server_cb);

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
        wolfSSL_CTX_set_psk_client_importer_callback(endpoint->wolfssl_context,
                                                     wolfssl_tls13_client_cb);

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

#include <errno.h>
#include <stdlib.h>

#include "asl_logging.h"
#include "asl_pkcs11.h"
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

#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)

static int dev_id_counter_endpoint = 0;

static int get_next_device_id_endpoint(void)
{
        int current_id = dev_id_counter_endpoint;

        dev_id_counter_endpoint = (dev_id_counter_endpoint + 1) % DEVICE_ID_MAX_ENDPOINT;

        return current_id + DEVICE_ID_OFFSET_ENDPOINT;
}

/* Configure the PKCS11 module for an endpoint.
 *
 * Returns 0 on success, negative error code on failure (error message is logged to the console).
 */
static int configure_pkcs11_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config)
{
        int ret = 0;

        if ((endpoint == NULL) || (config == NULL))
                return ASL_ARGUMENT_ERROR;

#if !defined(HAVE_PKCS11_STATIC) && !defined(HAVE_PKCS11_STATIC_V3)
        if (config->pkcs11.module_path == NULL)
                return ASL_ARGUMENT_ERROR;
#endif

        /* Load the PKCS#11 module library */
        if (endpoint->pkcs11_module.initialized == false)
        {
                asl_log(ASL_LOG_LEVEL_INF, "Initializing PKCS#11 module");

                endpoint->pkcs11_module.device_id = get_next_device_id_endpoint();

                /* Initialize the PKCS#11 library */
                int pkcs11_version = WC_PCKS11VERSION_3_2;
                ret = wc_Pkcs11_Initialize_ex(&endpoint->pkcs11_module.device,
                                              config->pkcs11.module_path,
                                              NULL,
                                              &pkcs11_version,
                                              "PKCS 11",
                                              NULL);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 library: %d", ret);
                if (pkcs11_version != WC_PCKS11VERSION_3_2)
                        asl_log(ASL_LOG_LEVEL_WRN, "No PQC capable PKCS#11 version: %d", pkcs11_version);

                /* Check if a PIN is provided */
                int pin_length = 0;
                if (config->pkcs11.module_pin != NULL)
                        pin_length = strlen(config->pkcs11.module_pin);

                /* Initialize the token */
                ret = wc_Pkcs11Token_Init(&endpoint->pkcs11_module.token,
                                          &endpoint->pkcs11_module.device,
                                          -1,
                                          NULL,
                                          (uint8_t const* const) config->pkcs11.module_pin,
                                          pin_length);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to initialize PKCS#11 token: %d", ret);

                /* Register the device with WolfSSL */
                ret = wc_CryptoCb_RegisterDevice(endpoint->pkcs11_module.device_id,
                                                 wc_Pkcs11_CryptoDevCb,
                                                 &endpoint->pkcs11_module.token);
                if (ret != 0)
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to register PKCS#11 callback: %d", ret);

                /* Create a persistent session with the secure element */
                ret = wc_Pkcs11Token_Open(&endpoint->pkcs11_module.token, 1);
                if (ret == 0)
                {
                        endpoint->pkcs11_module.initialized = true;
                        asl_log(ASL_LOG_LEVEL_INF, "PKCS#11 module initialized");
                }
                else
                {
                        endpoint->pkcs11_module.initialized = false;
                        ERROR_OUT(ASL_PKCS11_ERROR, "Unable to open PKCS#11 token: %d", ret);
                }

                if (config->pkcs11.use_for_all == true)
                {
                        wolfSSL_CTX_SetDevId(endpoint->wolfssl_context,
                                             endpoint->pkcs11_module.device_id);
                }
        }

        return 0;

cleanup:
        wc_CryptoCb_UnRegisterDevice(endpoint->pkcs11_module.device_id);
        wc_Pkcs11Token_Final(&endpoint->pkcs11_module.token);
        wc_Pkcs11_Finalize(&endpoint->pkcs11_module.device);

        return ret;
}

#endif /* KRITIS3M_ASL_ENABLE_PKCS11 */

int use_pkcs11_certificate_chain(asl_endpoint* endpoint,
                                 asl_endpoint_configuration const* config,
                                 char const* label)
{
#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
        int ret = 0;

        /* Initialize the PKCS#11 module */
        ret = configure_pkcs11_endpoint(endpoint, config);
        if (ret != 0)
                ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure PKCS#11 crypto module");

        asl_log(ASL_LOG_LEVEL_DBG, "Using external certificate chain with label \"%s\"", label);

        ret = wolfSSL_CTX_use_certificate_label(endpoint->wolfssl_context,
                                                label,
                                                endpoint->pkcs11_module.device_id);

        if (wolfssl_check_for_error(ret))
                ERROR_OUT(ASL_CERTIFICATE_ERROR, "Unable to load external certificate chain");

        ret = wolfSSL_CTX_use_certificate_chain_label(endpoint->wolfssl_context,
                                                      label,
                                                      endpoint->pkcs11_module.device_id);

cleanup:
        return ret;
#else
        asl_log(ASL_LOG_LEVEL_ERR,
                "PKCS#11 support is not compiled in, please compile with support enabled");

        return ASL_PKCS11_ERROR;
#endif
}

int use_pkcs11_private_key(asl_endpoint* endpoint,
                           asl_endpoint_configuration const* config,
                           char const* label)
{
#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
        int ret = 0;

        /* Initialize the PKCS#11 module */
        ret = configure_pkcs11_endpoint(endpoint, config);
        if (ret != 0)
                ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure PKCS#11 crypto module");

        asl_log(ASL_LOG_LEVEL_DBG, "Using external private key with label \"%s\"", label);

        /* Use keys on the secure element (this also loads the label for the alt key) */
        ret = wolfSSL_CTX_use_PrivateKey_Label(endpoint->wolfssl_context,
                                               label,
                                               endpoint->pkcs11_module.device_id);

cleanup:
        return ret;
#else
        asl_log(ASL_LOG_LEVEL_ERR,
                "PKCS#11 support is not compiled in, please compile with support enabled");

        return ASL_PKCS11_ERROR;
#endif
}

int use_pkcs11_alt_private_key(asl_endpoint* endpoint,
                               asl_endpoint_configuration const* config,
                               char const* label)
{
#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
        int ret = 0;

        if (endpoint->pkcs11_module.device_id == INVALID_DEVID)
                endpoint->pkcs11_module.device_id = get_next_device_id_endpoint();

        /* Initialize the PKCS#11 module */
        ret = configure_pkcs11_endpoint(endpoint, config);
        if (ret != 0)
                ERROR_OUT(ASL_PKCS11_ERROR, "Failed to configure long-term crypto module");

        asl_log(ASL_LOG_LEVEL_DBG, "Using external alternative private key with label \"%s\"", label);

        /* Use keys on the secure element (this also loads the label for the alt key) */
        ret = wolfSSL_CTX_use_AltPrivateKey_Label(endpoint->wolfssl_context,
                                                  label,
                                                  endpoint->pkcs11_module.device_id);

cleanup:
        return ret;
#else
        asl_log(ASL_LOG_LEVEL_ERR,
                "PKCS#11 support is not compiled in, please compile with support enabled");

        return ASL_PKCS11_ERROR;
#endif
}

void pkcs11_endpoint_cleanup(asl_endpoint* endpoint)
{
#if defined(KRITIS3M_ASL_ENABLE_PKCS11) && defined(HAVE_PKCS11)
        if (endpoint->pkcs11_module.initialized == true)
        {
                wc_Pkcs11Token_Final(&endpoint->pkcs11_module.token);
                wc_Pkcs11_Finalize(&endpoint->pkcs11_module.device);
                wc_CryptoCb_UnRegisterDevice(endpoint->pkcs11_module.device_id);
                endpoint->pkcs11_module.initialized = false;
        }
#endif
}

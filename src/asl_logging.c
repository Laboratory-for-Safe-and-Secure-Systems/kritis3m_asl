#include "asl_logging.h"
#include "asl.h"

#include "wolfssl/options.h"

#include "wolfssl/error-ssl.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

/* Internal logging variables */
static int32_t asl_log_level = ASL_LOG_LEVEL_ERR;
static asl_log_callback_t asl_log_callback = NULL;
static bool asl_log_enabled = false;

/* Internal method declarations */
void wolfssl_logging_callback(int level, const char* str);
void asl_default_log_callback(int32_t level, char const* message);

int asl_prepare_logging(asl_configuration const* config)
{
        asl_log_enabled = config->logging_enabled;

        /* Update the internal log level. */
        if ((config->log_level >= ASL_LOG_LEVEL_ERR) && (config->log_level <= ASL_LOG_LEVEL_DBG))
                asl_log_level = config->log_level;
        else
                return ASL_ARGUMENT_ERROR;

        /* Check if we have to enable WolfSSL internal logging */
        if ((asl_log_enabled == true) && (asl_log_level == ASL_LOG_LEVEL_DBG))
        {
                wolfSSL_SetLoggingCb(wolfssl_logging_callback);
                int ret = wolfSSL_Debugging_ON();
                if (ret != 0)
                        asl_log(ASL_LOG_LEVEL_WRN, "Debug output is not enabled, please compile with DEBUG_WOLFSSL defined");
        }

        if (config->log_callback != NULL)
                asl_log_callback = config->log_callback;
        else
                asl_log_callback = asl_default_log_callback;

        return ASL_SUCCESS;
}

/* Check return value for an error. Print error message in case. */
int wolfssl_check_for_error(int32_t ret)
{
        if (ret != WOLFSSL_SUCCESS)
        {
                if (ret < WOLFSSL_FAILURE)
                {
                        char errMsg[WOLFSSL_MAX_ERROR_SZ];
                        wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

                        if (asl_log_callback != NULL)
                                asl_log_callback(ASL_LOG_LEVEL_ERR, errMsg);
                }

                return -1;
        }

        return 0;
}

void asl_log(int32_t level, char const* message, ...)
{
        if (asl_log_enabled == false || level > asl_log_level)
                return;

        va_list args;
        va_start(args, message);

        char buffer[256];
        vsnprintf(buffer, sizeof(buffer), message, args);

        va_end(args);

        if (asl_log_callback != NULL)
                asl_log_callback(level, buffer);
}

void wolfssl_logging_callback(int level, const char* str)
{
        (void) level;

        if (asl_log_enabled == true && asl_log_callback != NULL)
                asl_log_callback(ASL_LOG_LEVEL_DBG, str);
}

void asl_default_log_callback(int32_t level, char const* message)
{
        if (asl_log_enabled == false || level > asl_log_level)
                return;

        printf("%s\n", message);
}

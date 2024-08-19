#include "asl.h"
#include "asl_logging.h"

#include "wolfssl/options.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/memory.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"
#include "wolfssl/error-ssl.h"


/* Internal logging variables */
static int32_t log_level = ASL_LOG_LEVEL_ERR;
static asl_custom_log_callback log_callback = NULL;
static bool log_enabled = false;

/* Internal method declarations */
void wolfssl_logging_callback(int level, const char* str);
void asl_default_log_callback(int32_t level, char const* message);


/* Enable/disable logging infrastructure.
 *
 * Parameter is a boolean value to enable or disable logging.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_enable_logging(bool enable)
{
	log_enabled = enable;

	/* Check if we have to enable WolfSSL internal logging */
	if (log_enabled == true && log_level == ASL_LOG_LEVEL_DBG)
	{
    		int ret = wolfSSL_Debugging_ON();
		if (ret != 0)
		{
			asl_log(ASL_LOG_LEVEL_WRN, "Debug output is not compiled in, please compile with DEBUG_WOLFSSL preprocessor makro defined");
		}
	}
	else
		wolfSSL_Debugging_OFF();

	return ASL_SUCCESS;
}


/* Set a custom logging callback.
 *
 * Parameter is a function pointer to the custom logging callback.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_set_custom_log_callback(asl_custom_log_callback new_callback)
{
	/* Update the internal pointer to the callback. */
	if (new_callback != NULL)
		log_callback = new_callback;
	else
		log_callback = asl_default_log_callback;

        wolfSSL_SetLoggingCb(wolfssl_logging_callback);

	return ASL_SUCCESS;
}


/* Update the log level.
 *
 * Parameter is the new log level.
 *
 * Returns ASL_SUCCESS on success, negative error code in case of an error.
 */
int asl_set_log_level(int32_t new_log_level)
{
	/* Update the internal log level. */
	if ((new_log_level >= ASL_LOG_LEVEL_ERR) && (new_log_level <= ASL_LOG_LEVEL_DBG))
		log_level = new_log_level;
	else
		return ASL_ARGUMENT_ERROR;

	/* Check if we have to enable WolfSSL internal logging */
	if (log_enabled == true && log_level == ASL_LOG_LEVEL_DBG)
	{
    		int ret = wolfSSL_Debugging_ON();
		if (ret != 0)
		{
			asl_log(ASL_LOG_LEVEL_WRN, "Debug output is not compiled in, please compile with DEBUG_WOLFSSL preprocessor makro defined");
		}
	}
	else
		wolfSSL_Debugging_OFF();

	return ASL_SUCCESS;
}



/* Check return value for an error. Print error message in case. */
int wolfssl_check_for_error(int32_t ret)
{
	if (ret != WOLFSSL_SUCCESS)
	{
		char errMsg[WOLFSSL_MAX_ERROR_SZ];
		wolfSSL_ERR_error_string_n(ret, errMsg, sizeof(errMsg));

		if (log_callback != NULL)
			log_callback(ASL_LOG_LEVEL_ERR, errMsg);

		return -1;
	}

	return 0;
}


void asl_log(int32_t level, char const* message, ...)
{
	if (log_enabled == false || level > log_level)
		return;

	va_list args;
	va_start(args, message);

	char buffer[256];
	vsnprintf(buffer, sizeof(buffer), message, args);

	va_end(args);

	if (log_callback != NULL)
		log_callback(level, buffer);

}


void wolfssl_logging_callback(int level, const char* str)
{
	(void) level;

	if (log_enabled == true && log_callback != NULL)
		log_callback(ASL_LOG_LEVEL_DBG, str);
}


void asl_default_log_callback(int32_t level, char const* message)
{
	if (log_enabled == false || level > log_level)
		return;

	printf("%s\n", message);
}

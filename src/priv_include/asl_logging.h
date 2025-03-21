#ifndef ASL_LOGGING_H
#define ASL_LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "asl.h"

/* Internal logging methods used within the library */
int asl_prepare_logging(asl_configuration const* config);
int wolfssl_check_for_error(int32_t ret);
void asl_log(int32_t level, char const* message, ...);

#endif /* ASL_LOGGING_H */
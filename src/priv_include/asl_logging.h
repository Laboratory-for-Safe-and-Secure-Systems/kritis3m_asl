#ifndef ASL_LOGGING_H
#define ASL_LOGGING_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Internal logging methods used within the library */
int wolfssl_check_for_error(int32_t ret);
void asl_log(int32_t level, char const* message, ...);

#endif /* ASL_LOGGING_H */
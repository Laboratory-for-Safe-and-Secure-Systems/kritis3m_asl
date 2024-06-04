#ifndef ASL_LOGGING_H
#define ASL_LOGGING_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Internal logging methods used within the library */
int errorOccured(int32_t ret);
void asl_log(int32_t level, char const* message, ...);

#endif /* ASL_LOGGING_H */
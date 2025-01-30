#ifndef ASL_PSK_H
#define ASL_PSK_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "asl.h"
#include "asl_types.h"

int psk_setup_general(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

int psk_setup_server(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

int psk_setup_client(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

void psk_endpoint_cleanup(asl_endpoint* endpoint);

#endif /* ASL_PSK_H */
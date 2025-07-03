#ifndef ASL_PKCS11_H
#define ASL_PKCS11_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "asl.h"
#include "asl_types.h"

int configure_pkcs11_endpoint(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

int use_pkcs11_root_certificates(asl_endpoint* endpoint, asl_endpoint_configuration const* config);

int use_pkcs11_certificate_chain(asl_endpoint* endpoint,
                                 asl_endpoint_configuration const* config,
                                 char const* label);

int use_pkcs11_private_key(asl_endpoint* endpoint,
                           asl_endpoint_configuration const* config,
                           char const* label);

int use_pkcs11_alt_private_key(asl_endpoint* endpoint,
                               asl_endpoint_configuration const* config,
                               char const* label);

void pkcs11_endpoint_cleanup(asl_endpoint* endpoint);

#endif /* ASL_PKCS11_H */

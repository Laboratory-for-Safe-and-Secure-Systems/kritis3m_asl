#ifndef WOLFSSSL_PKCS11_PQC_H
#define WOLFSSSL_PKCS11_PQC_H

#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

/* Data structure for a PKCS#11 module */
typedef struct
{
#ifdef HAVE_PKCS11
	Pkcs11Dev device;
	Pkcs11Token token;
#endif
	bool initialized;
}
asl_pkcs11_module;


/* Get the device id of the secure element */
int secure_element_device_id(void);


/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int pkcs11_import_pem_key(asl_pkcs11_module* module, uint8_t const* pem_buffer, uint32_t pem_size,
			  char const* label);


#endif /* WOLFSSSL_PKCS11_PQC_H */

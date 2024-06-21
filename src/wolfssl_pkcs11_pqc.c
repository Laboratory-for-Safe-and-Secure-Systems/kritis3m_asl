
#include "secure_element/wolfssl_pkcs11_pqc.h"

#include "wolfssl/wolfcrypt/cryptocb.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/wc_pkcs11.h"

#include "asl.h"
#include "asl_logging.h"

#define DEVICE_ID_SECURE_ELEMENT 1

static char private_key_id[] = "ENTITY_KEY";
static size_t private_key_id_size = sizeof(private_key_id) - 1;

static char additional_private_key_id[] = "ENTITY_ALT_KEY";
static size_t additional_private_key_id_size = sizeof(additional_private_key_id) - 1;


#ifdef HAVE_PKCS11
static dilithium_key* create_dilithium_key_from_buffer(int key_format, uint8_t const* der_buffer,
						uint32_t der_size, uint8_t const* id, int len);
static falcon_key* create_falcon_key_from_buffer(int key_format, uint8_t const* der_buffer,
					  uint32_t der_size, uint8_t const* id, int len);
static RsaKey* create_rsa_key_from_buffer(uint8_t const* der_buffer, uint32_t der_size,
				   uint8_t const* id, int len);
static ecc_key* create_ecc_key_from_buffer(uint8_t const* der_buffer, uint32_t der_size,
				    uint8_t const* id, int len);
#endif /* HAVE_PKCS11 */


/* Get the id of the static private key */
uint8_t const* secure_element_private_key_id(void)
{
        return (uint8_t const*) private_key_id;
}


/* Get the size of the id of the static private key */
uint32_t secure_element_private_key_id_size(void)
{
        return private_key_id_size;
}


/* Get the id of the additional static private key */
uint8_t const* secure_element_additional_private_key_id(void)
{
	return (uint8_t const*) additional_private_key_id;
}


/* Get the size of the id of the additional static private key */
uint32_t secure_element_additional_private_key_id_size(void)
{
	return additional_private_key_id_size;
}


/* Get the device id of the secure element */
int secure_element_device_id(void)
{
        return DEVICE_ID_SECURE_ELEMENT;
}


/* Import the public/private key pair in the given PEM file into the secure element.
 *
 * Returns 0 on success, -1 in case of an error (error message is logged to the console).
 */
int pkcs11_import_pem_key(asl_pkcs11_module* module, uint8_t const* pem_buffer, uint32_t pem_size,
			  uint8_t const* id, int len)
{
#ifdef HAVE_PKCS11
        DerBuffer* der = NULL;
	EncryptedInfo info;
	int keyFormat = 0;
	int type = 0;
	void* key = NULL;
	int ret = 0;
	uint32_t consumed = 0;

	memset(&info, 0, sizeof(EncryptedInfo));

	/* As the PEM file may contain more than one private key in case of a hybrid certificate,
	 * we have to parse the file in a loop. */
	while ((consumed < pem_size) && (ret == 0))
	{
		/* Convert key to DER (binary) */
		ret = PemToDer(pem_buffer + consumed, pem_size - consumed, PRIVATEKEY_TYPE, &der, NULL,
			&info, &keyFormat);
		if (ret < 0)
		{
			FreeDer(&der);
			asl_log(ASL_LOG_LEVEL_ERR, "Error converting private key to DER");
			return -1;
		}
		consumed += info.consumed;

		/* Check which key type we have */
		if (keyFormat == RSAk)
		{
			/* Create the key object */
			key = create_rsa_key_from_buffer(der->buffer, der->length, id, len);

			type = PKCS11_KEY_TYPE_RSA;
		}
		else if (keyFormat == ECDSAk)
		{
			/* Create the key object */
			key = create_ecc_key_from_buffer(der->buffer, der->length, id, len);

			type = PKCS11_KEY_TYPE_EC;
		}
		else if ((keyFormat == FALCON_LEVEL1k) || (keyFormat == FALCON_LEVEL5k))
		{
			/* Create the key object */
			key = create_falcon_key_from_buffer(keyFormat, der->buffer, der->length,
							id, len);

			type = PKCS11_KEY_TYPE_FALCON;
		}
		else if ((keyFormat == DILITHIUM_LEVEL2k) || (keyFormat == DILITHIUM_LEVEL3k) ||
			(keyFormat == DILITHIUM_LEVEL5k))
		{
			/* Create the key object */
			key = create_dilithium_key_from_buffer(keyFormat, der->buffer, der->length,
							id, len);

			type = PKCS11_KEY_TYPE_DILITHIUM;
		}

		if (key == NULL)
		{
			FreeDer(&der);
			asl_log(ASL_LOG_LEVEL_ERR, "Error creating private key object");
			return -1;
		}

		/* Import the key into the secure element */
		ret = wc_Pkcs11StoreKey_ex(&module->token, type, 1, key, 1);
		if (ret != 0)
		{
			asl_log(ASL_LOG_LEVEL_ERR, "Error importing private key into secure element: %d", ret);
			ret = -1;
		}

		/* Free key */
		switch (keyFormat)
		{
		case RSAk:
			wc_FreeRsaKey(key);
			break;
		case ECDSAk:
			wc_ecc_free(key);
			break;
		case FALCON_LEVEL1k:
		case FALCON_LEVEL5k:
			wc_falcon_free(key);
			break;
		case DILITHIUM_LEVEL2k:
		case DILITHIUM_LEVEL3k:
		case DILITHIUM_LEVEL5k:
			wc_dilithium_free(key);
			break;
		}
		free(key);

		FreeDer(&der);
	}

	return ret;
#else
	(void)module;
	(void)pem_buffer;
	(void)pem_size;
	(void)id;
	(void)len;

	asl_log(ASL_LOG_LEVEL_ERR, "PKCS#11 support is not enabled");

	return -1;
#endif /* HAVE_PKCS11 */
}


#ifdef HAVE_PKCS11
/* Fill a new dilithium key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 *
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
dilithium_key* create_dilithium_key_from_buffer(int key_format, uint8_t const* der_buffer,
						uint32_t der_size, uint8_t const* id, int len)
{
	word32 idx = 0;

	/* Allocate new key */
	dilithium_key* key = (dilithium_key*) malloc(sizeof(dilithium_key));
	if (key == NULL)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error allocating temporary private key");
		return NULL;
	}

	int ret = wc_dilithium_init_id(key, id, len, NULL, INVALID_DEVID);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error creating new key: %d", ret);
		free(key);
		return NULL;
	}

	/* Set level */
	if (key_format == DILITHIUM_LEVEL2k)
	{
		wc_dilithium_set_level(key, 2);
	}
	else if (key_format == DILITHIUM_LEVEL3k)
	{
		wc_dilithium_set_level(key, 3);
	}
	else if (key_format == DILITHIUM_LEVEL5k)
	{
		wc_dilithium_set_level(key, 5);
	}

	/* Import the actual private key from the DER buffer */
	ret = wc_Dilithium_PrivateKeyDecode(der_buffer, &idx, key, der_size);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error parsing the DER key: %d", ret);
		wc_dilithium_free(key);
		free(key);
		return NULL;
	}

	return key;
}


/* Fill a new falcon key with data from the provided DER buffer. The dilithium level is
 * encoded in the key_format parameter. The memory for the key is allocated by this method
 * and must be freed by the caller.
 *
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
falcon_key* create_falcon_key_from_buffer(int key_format, uint8_t const* der_buffer,
					  uint32_t der_size, uint8_t const* id, int len)
{
        /* Allocate new key */
	falcon_key* key = (falcon_key*) malloc(sizeof(falcon_key));
	if (key == NULL)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error allocating temporary private key");
		return NULL;
	}

	int ret = wc_falcon_init_id(key, id, len, NULL, INVALID_DEVID);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error creating new key: %d", ret);
		free(key);
		return NULL;
	}

	/* Set level */
	if (key_format == FALCON_LEVEL1k)
	{
		wc_falcon_set_level(key, 1);
	}
	else if (key_format == FALCON_LEVEL5k)
	{
		wc_falcon_set_level(key, 5);
	}

	/* Import the actual private key from the DER buffer */
	ret = wc_falcon_import_private_key(der_buffer, der_size, NULL, 0, key);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error parsing the DER key: %d", ret);
		wc_falcon_free(key);
		free(key);
		return NULL;
	}

	return key;
}


/* Fill a new RSA key with data from the provided DER buffer. The memory for the key is
 * allocated by this method and must be freed by the caller.
 *
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
RsaKey* create_rsa_key_from_buffer(uint8_t const* der_buffer, uint32_t der_size,
				   uint8_t const* id, int len)
{
	/* Allocate new key */
	RsaKey* key = (RsaKey*) malloc(sizeof(RsaKey));
	if (key == NULL)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error allocating temporary private key");
		return NULL;
	}

	int ret = wc_InitRsaKey_Id(key, (uint8_t*)id, len, NULL, INVALID_DEVID);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error creating new key: %d", ret);
		free(key);
		return NULL;
	}

	/* Import the actual private key from the DER buffer */
	uint32_t index = 0;
	ret = wc_RsaPrivateKeyDecode(der_buffer, &index, key, der_size);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error parsing the DER key: %d", ret);
		wc_FreeRsaKey(key);
		free(key);
		return NULL;
	}

	return key;
}


/* Fill a new ECC key with data from the provided DER buffer. The memory for the key is
 * allocated by this method and must be freed by the caller.
 *
 * Returns a pointer to the new key on success, NULL in case of an error (error message is
 * logged to the console).
 */
ecc_key* create_ecc_key_from_buffer(uint8_t const* der_buffer, uint32_t der_size,
				    uint8_t const* id, int len)
{
	/* Allocate new key */
	ecc_key* key = (ecc_key*) malloc(sizeof(ecc_key));
	if (key == NULL)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error allocating temporary private key");
		return NULL;
	}

	int ret = wc_ecc_init_id(key, (uint8_t*)id, len, NULL, INVALID_DEVID);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error creating new key: %d", ret);
		free(key);
		return NULL;
	}

	/* Import the actual private key from the DER buffer */
	uint32_t index = 0;
	ret = wc_EccPrivateKeyDecode(der_buffer, &index, key, der_size);
	if (ret != 0)
	{
		asl_log(ASL_LOG_LEVEL_ERR, "Error parsing the DER key: %d", ret);
		wc_ecc_free(key);
		free(key);
		return NULL;
	}

	return key;
}
#endif /* HAVE_PKCS11 */


#if defined(__ZEPHYR__) && defined(CONFIG_SECURE_ELEMENT_SUPPORT)

#include <zephyr/drivers/i2c.h>
#include "secure_element/CardOS_IoT_I2C_driver.h"


I2C_RV setupI2C(i2cParameters *params)
{
	const struct device* const dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));

	// printk("main : setupI2C\n");

	if (!device_is_ready(dev))
	{
		printk("%s: device not ready.\n", dev->name);
		return I2C_E_CONFIG_ERROR;
	}
	// else
	// {
	// 	printk("%s: device ready.\n", dev->name);
	// }

	/* configure i2c */
	uint32_t i2c_cfg = I2C_SPEED_SET(I2C_SPEED_FAST) | I2C_MODE_CONTROLLER;
	if (i2c_configure(dev, i2c_cfg))
	{
		printk("i2c config failed.\n");
		return I2C_E_CONFIG_ERROR;
	}
	else
	{
		printk("%s: device configured.\n", dev->name);
	}

	params->address = 0x38;

	// printk("main : setupI2C ... done.\n");

	return I2C_S_SUCCESS;
}


I2C_RV I2C_RW(void *context, unsigned char *packet, int packetLength, unsigned char *response, int *responseLength)
{
	const struct device* const dev = DEVICE_DT_GET(DT_NODELABEL(i2c1));
	i2cParameters* params = (i2cParameters*) context;

	// printk("main : I2C_RW\n");

	uint8_t *rpdu = response;
	int pos = 0;

	int ret = 0;
	int counter = 100;

	int readLen = 0;

	uint8_t lrc = 0;
	uint8_t lrcExpected = 0;

	// calculateLrcI2C(apdu, sizeof(apdu), 0x01);

	// printk("Write\n");
	// for (int i = 0; i < packetLength; i++)
	// {
	// 	printk("%02X ", packet[i]);
	// }
	// printk("\n");

	if (i2c_write(dev, packet, packetLength, params->address))
	{
		printk("i2c write failed.\n");
		return I2C_E_RW_ERROR;
	}

	// k_msleep(200);

	while (*rpdu == 0xFF)
	{
		/* read data */
		if (i2c_read(dev, &(rpdu[pos]), 1, params->address))
		{
			printk("i2c read failed.\n");
		}
		counter--;
		// printk("Wait.\n");
		k_msleep(100);

		if (counter == 0)
		{
			printk("Timeout.\n");
			return I2C_E_RW_ERROR;
		}
	}

	pos++;

	if (i2c_read(dev, &(rpdu[pos]), 1, params->address))
	{
		printk("i2c read failed.\n");
	}

	readLen = (rpdu[0] << 8) + rpdu[1];

	pos++;

	// printk("Len: %d\n", readLen);

	/* read data */
	while ((ret = i2c_read(dev, &(rpdu[pos++]), 1, params->address)) == 0)
	{
		if (pos == readLen + 2)
			break;
	}

	// lrc
	if (i2c_read(dev, &(rpdu[pos++]), 1, params->address))
	{
		printk("i2c read failed.\n");
	}

	lrc = rpdu[pos - 1];
	// NOTE: function check from 0 to len-1
	lrcExpected = calculateLrcI2C(rpdu, pos, 0x00);

	// printk("LRC: %02X, Expected: %02X CHK: %s\n", lrc, lrcExpected, ((lrc == lrcExpected) ? "OK" : "FAIL"));

	// printk("Read\n");
	// for (int i = 2; i < readLen + 2; i++)
	// {
	// 	printk("%02X ", rpdu[i]);
	// }
	// printk("\n");

	*responseLength = pos;

	return I2C_S_SUCCESS;
}

#endif /* __ZEPHYR__ && CONFIG_SECURE_ELEMENT_SUPPORT */

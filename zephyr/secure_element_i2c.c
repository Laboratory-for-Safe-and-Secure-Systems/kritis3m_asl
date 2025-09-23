
#if defined(__ZEPHYR__) && defined(CONFIG_SECURE_ELEMENT_SUPPORT)

#include "CardOS_IoT_I2C_driver.h"
#include "winscard.h"
#include <zephyr/drivers/i2c.h>

static SCARDCONTEXT hContext = 0;
static SCARDHANDLE hCard = 0;

I2C_RV setupI2C(i2cParameters* params)
{
        params->address = 0x38;

        LPCSTR szReader = "testReader";
        DWORD dwPreferredProtocols = SCARD_PROTOCOL_T1;
        DWORD dwActiveProtocol;
        DWORD dwShareMode = SCARD_SHARE_EXCLUSIVE;
        LONG res;

        /* Init */
        res = SCardEstablishContext(SCARD_SCOPE_GLOBAL, NULL, NULL, &hContext);
        if (res != SCARD_S_SUCCESS)
                return I2C_E_CONFIG_ERROR;

        /* A2R */
        res = SCardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols, &hCard, &dwActiveProtocol);
        if ((res != SCARD_S_SUCCESS) || (dwActiveProtocol != SCARD_PROTOCOL_T1))
                return I2C_E_CONFIG_ERROR;

        return I2C_S_SUCCESS;
}

I2C_RV I2C_RW(void* context, unsigned char* packet, int packetLength, unsigned char* response, int* responseLength)
{
        SCARD_IO_REQUEST sendPci;
        sendPci.dwProtocol = SCARD_PROTOCOL_T1;
        sendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);

        SCARD_IO_REQUEST recvPci;

        BYTE recvBuffer[512];
        DWORD recvLength = sizeof(recvBuffer);

        LONG res;

        /* Send the APDU, stored in the `packet` buffer (the buffer includes an already calculated
         * LRC byte). Reduce the length by one to exclude this last LRC byte. The APDU response is
         * stored in the temporary buffer `recvBuffer`. */
        res = SCardTransmit(hCard, &sendPci, packet, packetLength - 1, &recvPci, recvBuffer, &recvLength);
        if (res != SCARD_S_SUCCESS)
                return I2C_E_RW_ERROR;

        /* Build the I2C frame */
        response[0] = (recvLength >> 8) & 0xFF;
        response[1] = recvLength & 0xFF;
        memcpy(&response[2], recvBuffer, recvLength);
        response[2 + recvLength] = calculateLrcI2C(response, 2 + recvLength, 0x00);

        *responseLength = recvLength + 3;

        return I2C_S_SUCCESS;
}

#endif /* __ZEPHYR__ && CONFIG_SECURE_ELEMENT_SUPPORT */

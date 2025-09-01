
#if defined(__ZEPHYR__) && defined(CONFIG_SECURE_ELEMENT_SUPPORT)

#include "CardOS_IoT_I2C_driver.h"
#include <zephyr/drivers/i2c.h>
#include "T1_main.h"
#include "T1_protocol_param.h"
#include "winscard.h"

LPSCARDHANDLE phCard;
SCARDHANDLE hCard = 1;

I2C_RV setupI2C(i2cParameters* params)
{
        params->address = 0x38;
        //Init
        DWORD dwScope = SCARD_SCOPE_GLOBAL;
        LPSCARDCONTEXT phContext = NULL;
        SCardEstablishContext(dwScope, NULL, NULL, phContext);

        //A2R
        SCARDCONTEXT hContext = NULL;
        LPCSTR szReader = "testReader";
        DWORD dwPreferredProtocols = SCARD_PROTOCOL_T1;
        phCard = &hCard;
        LPDWORD pdwActiveProtocol = NULL;
        DWORD dwShareMode = SCARD_SHARE_EXCLUSIVE;

        SCardConnect(hContext, szReader, dwShareMode, dwPreferredProtocols, phCard, pdwActiveProtocol);

        int32_t resp_status = 0; /* Communication Response status */

        /*------- Send IFSD request --------------------------------------------------*/

        /* Negotiate IFSD: we indicate to the card a new IFSD that the reader can support */
        resp_status = T1_Negotiate_IFSD(&SCInterface, NAD, IFSD_VALUE);

        /* If the IFSD request communication has failed */
        if (resp_status < 0)
        {
                /* ---IFSD communication error--- */
        }

        return I2C_S_SUCCESS;
}

I2C_RV I2C_RW(void* context, unsigned char* packet, int packetLength, unsigned char* response, int* responseLength)
{
        SCARD_IO_REQUEST sendPci;
        sendPci.dwProtocol = SCARD_PROTOCOL_T1;
        sendPci.cbPciLength = sizeof(SCARD_IO_REQUEST);

        DWORD RecvLength = 512;

        const SCARD_IO_REQUEST* pioSendPci = &sendPci;
        LPCBYTE pbSendBuffer = packet;       // buffer that has to be transmitted
        DWORD cbSendLength = packetLength - 1; // length of the pbSendBuffer
        SCARD_IO_REQUEST* pioRecvPci;              // out
        LPBYTE pbRecvBuffer;                       // out
        BYTE recvBuffer[512];
        LPDWORD pcbRecvLength = &RecvLength;       // expected maximum received answer length

        SCardTransmit(hCard, pioSendPci, pbSendBuffer, cbSendLength, pioRecvPci, recvBuffer, pcbRecvLength);

        /* Build the I2C frame */
        response[0] = (*pcbRecvLength >> 8) & 0xFF;
        response[1] = *pcbRecvLength & 0xFF;
        memcpy(&response[2], recvBuffer, *pcbRecvLength);
        response[2 + *pcbRecvLength] = calculateLrcI2C(response, 2 + *pcbRecvLength, 0x00);

        *responseLength = *pcbRecvLength + 3;

        return I2C_S_SUCCESS;
}

#endif /* __ZEPHYR__ && CONFIG_SECURE_ELEMENT_SUPPORT */


#if defined(__ZEPHYR__) && defined(CONFIG_SECURE_ELEMENT_SUPPORT)

#include "CardOS_IoT_I2C_driver.h"
#include <zephyr/drivers/i2c.h>

I2C_RV setupI2C(i2cParameters* params)
{
        const struct device* const dev = DEVICE_DT_GET(DT_ALIAS(pico_i2c));

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

I2C_RV I2C_RW(void* context, unsigned char* packet, int packetLength, unsigned char* response, int* responseLength)
{
        const struct device* const dev = DEVICE_DT_GET(DT_ALIAS(pico_i2c));
        i2cParameters* params = (i2cParameters*) context;

        // printk("main : I2C_RW\n");

        uint8_t* rpdu = response;
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

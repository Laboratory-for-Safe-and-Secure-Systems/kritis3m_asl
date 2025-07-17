
#if defined(__ZEPHYR__) && defined(CONFIG_SECURE_ELEMENT_SUPPORT)

#include "CardOS_IoT_I2C_driver.h"
#include <zephyr/drivers/i2c.h>

I2C_RV setupI2C(i2cParameters* params)
{
        const struct device* const dev = DEVICE_DT_GET(DT_ALIAS(pico_i2c));

        if (!device_is_ready(dev))
        {
                printk("%s: device not ready.\n", dev->name);
                return I2C_E_CONFIG_ERROR;
        }

        /* configure i2c */
        uint32_t i2c_cfg = I2C_SPEED_SET(I2C_SPEED_FAST) | I2C_MODE_CONTROLLER;
        if (i2c_configure(dev, i2c_cfg))
        {
                printk("i2c config failed.\n");
                return I2C_E_CONFIG_ERROR;
        }

        params->address = 0x38;

        return I2C_S_SUCCESS;
}

I2C_RV I2C_RW(void* context, unsigned char* packet, int packetLength, unsigned char* response, int* responseLength)
{
        const struct device* const dev = DEVICE_DT_GET(DT_ALIAS(pico_i2c));
        i2cParameters* params = (i2cParameters*) context;

        uint8_t* rpdu = response;
        int pos = 0;

        int ret = 0;
        int counter = 400;

        int readLen = 0;

        uint8_t lrc = 0;
        uint8_t lrcExpected = 0;

        if (i2c_write(dev, packet, packetLength, params->address))
        {
                printk("i2c write failed.\n");
                return I2C_E_RW_ERROR;
        }

        while (*rpdu == 0xFF)
        {
                k_msleep(25);

                /* read data */
                if (i2c_read(dev, &(rpdu[pos]), 1, params->address))
                {
                        printk("i2c read failed.\n");
                }
                counter--;

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

        *responseLength = pos;

        return I2C_S_SUCCESS;
}

#endif /* __ZEPHYR__ && CONFIG_SECURE_ELEMENT_SUPPORT */

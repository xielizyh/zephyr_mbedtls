/**
  ******************************************************************************
  * @file			base64.c
  * @brief			base64 function
  * @author			Xli
  * @email			xieliyzh@163.com
  * @version		1.0.0
  * @date			2020-07-07
  * @copyright		2020, CMIoT Co.,Ltd. All rights reserved
  ******************************************************************************
**/

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/base64.h"
/* Private constants ---------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
#define mbedtls_printf  printf

/* Private typedef -----------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
static uint8_t msg[] = 
{
    0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e
};


/* Private function ----------------------------------------------------------*/

/**=============================================================================
 * @brief           打印
 *
 * @param[in]       none
 *
 * @return          none
 *============================================================================*/
void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for(uint32_t i = 0; i < len; i++) {
        mbedtls_printf("%02x ", msg[i]);
    }
    mbedtls_printf("\n");
}

/**=============================================================================
 * @brief           main
 *
 * @param[in]       none
 *
 * @return          0
 *============================================================================*/
int main(void)
{
    size_t len;
    uint8_t rst[512];

    len = sizeof(msg);
    dump_buf("\n    base64 message: ", msg, len);

    mbedtls_base64_encode(rst, sizeof(rst), &len, msg, len);
    mbedtls_printf("    base64 encode[%d]: %s\n", (int)len, rst);

    mbedtls_base64_decode(rst, sizeof(rst), &len, rst, len);
    dump_buf("    base64 decode: ", rst, len);
    printf("\n");

    return 0;
}
/**
 ***********************************************************************************************************************
 * Copyright (c) 2020, China Mobile Communications Group Co.,Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @file        main.c
 *
 * @brief       main functions.
 *
 * @revision
 * Date         Author          Notes
 * 2020-07-20   XieLi           First Version
 ***********************************************************************************************************************
 */

#include <zephyr.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/base64.h"
#include "mbedtls/platform.h"

static uint8_t msg[] = 
{
    0x14, 0xfb, 0x9c, 0x03, 0xd9, 0x7e
};


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
 * @return          none
 *============================================================================*/
void main(void)
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
}
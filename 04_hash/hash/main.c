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
 * 2020-07-15   XieLi           First Version
 ***********************************************************************************************************************
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mbedtls/md.h>
#include <mbedtls/platform.h>

/**
 ***********************************************************************************************************************
 * @brief           Print 
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static void dump_buf(char *info, uint8_t *buf, uint32_t len)
{
    mbedtls_printf("%s", info);
    for (uint32_t i = 0; i < len; i++)
    {
        mbedtls_printf("%s%02X%s", i % 16 == 0 ? "\n\t":" ", buf[i], i == len - 1 ? "\n":"");
    }
    mbedtls_printf("\n");
}

/**
 ***********************************************************************************************************************
 * @brief           Main
 *
 * @param[in]       none
 *
 * @return          none
 * 
 * @todo            解决malloc的宏定义问题
 ***********************************************************************************************************************
 */
int main(void)
{
    uint8_t digest[32] = {0};
    char *msg = "abc";
    int ret = 0;
    int exit_code = MBEDTLS_EXIT_FAILURE;

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = NULL;
    //mbedtls_platform_set_printf(printf);

    mbedtls_md_init(&ctx);
    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    ret = mbedtls_md_setup(&ctx, info, 0);
    if (ret)
    {
        mbedtls_printf("mbedtls_md_setup: err=%s0x%x\n", ret < 0 ? "-" : "", ret < 0 ? -ret : ret);
    }
    mbedtls_printf("\nmd info setup, name: %s, digest size: %d\n", mbedtls_md_get_name(info), mbedtls_md_get_size(info));

    ret = mbedtls_md_starts(&ctx);
    if (ret)
    {
        mbedtls_printf("mbedtls_md_starts: err=%s0x%x\n", ret < 0 ? "-" : "", ret < 0 ? -ret : ret);
    }
    ret = mbedtls_md_update(&ctx, msg, strlen(msg));
    if (ret)
    {
        mbedtls_printf("mbedtls_md_update: err=%s0x%x\n", ret < 0 ? "-" : "", ret < 0 ? -ret : ret);
    }
    ret = mbedtls_md_finish(&ctx, digest);
    if (ret)
    {
        mbedtls_printf("mbedtls_md_finish: err=%s0x%x\n", ret < 0 ? "-" : "", ret < 0 ? -ret : ret);
    }
    
    dump_buf("\nmd sha-256 digest:", digest, sizeof(digest));

    mbedtls_md_free(&ctx);

    return 0;
}
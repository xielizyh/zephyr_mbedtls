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

#ifdef CONFIG_ZEPHYR_ENV
//#include <zephyr.h>
//#include <random/rand32.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "ca_cert.h"

#if 0
#define SERVER_ADDR         "iotwuxi.org"
#define SERVER_PORT         "442"
#define HOST_NAME           "iotwuxi.org"
#define GET_REQUEST         "GET /index.html HTTP/1.0\r\n\r\n"
#else       
#define SERVER_ADDR         "localhost"
#define SERVER_PORT         "442"
#define HOST_NAME           "xieli.org"     /* 注意需要和证书名称中CN(Common Name)一致 */
#define GET_REQUEST         "GET /index.html HTTP/1.0\r\n\r\n"
#endif 

#if defined(MBEDTLS_DEBUG_C)
#include "mbedtls/debug.h"
#define DEBUG_THRESHOLD 4

static void my_debug(void *ctx, int level,
                     const char *file, int line, const char *str)
{
    const char *p, *basename;

    /* Extract basename from file */
    for (p = basename = file; *p != '\0'; p++)
    {
        if (*p == '/' || *p == '\\')
        {
            basename = p + 1;
        }
    }

    printf("%s:%04d: |%d| %s", basename, line, level, str);
}
#endif

/* assert_exit */
#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

/**
 ***********************************************************************************************************************
 * @brief           熵源接口
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static int entropy_source(void *data, uint8_t *output, size_t len, size_t *olen)
{
    uint32_t seed = 0;
    //ARG_UNUSED(data);
#ifdef CONFIG_ZEPHYR_ENV
    seed = sys_rand32_get();
#else
    seed = rand();
#endif
    if (len > sizeof(seed))
    {
        len = sizeof(seed);
    }
    memcpy(output, &seed, len);

    *olen = len;

    return 0;
}

/**
 ***********************************************************************************************************************
 * @brief           Main
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
void main(void)
{
#if 0
    time_t t;
    for (uint8_t i = 0; i < 16; i++)
    {
        time(&t);
        printf("t=%ld\n", t);
        sleep(1);
    }
#endif

    int ret, len = 0;
    unsigned char buf[256] = {0};
    const char *pers = "tls_client";       /* 个性化字符串 */
    mbedtls_entropy_context entropy;        /* 熵源 */
    mbedtls_ctr_drbg_context ctr_drbg;      /* 随机数 */
    //mbedtls_platform_set_printf(printf);
    //mbedtls_platform_set_snprintf(snprintf);

    mbedtls_x509_crt cert;                  /* x509证书结构体 */
    mbedtls_ssl_context ssl;                /* 网络结构体 */
    mbedtls_ssl_config conf;                /* ssl结构体 */
    mbedtls_net_context ctx;                /* ssl配置结构体 */
    mbedtls_net_init(&ctx);                 /* 初始化网络结构体 */
    mbedtls_ssl_init(&ssl);                 /* 初始化ssl结构体 */
    mbedtls_ssl_config_init(&conf);         /* 初始化ssl配置结构体 */
    mbedtls_x509_crt_init(&cert);            /* 初始化x509证书结构体 */

    /* 随机数结构体初始化 */
    mbedtls_ctr_drbg_init(&ctr_drbg);
    printf("\n  . Seeding the random number generator...");
    /* 熵源结构体初始化 */
    mbedtls_entropy_init(&entropy);
    /* 添加熵源接口，设置熵源属性 */
    mbedtls_entropy_add_source(&entropy, entropy_source, NULL, MBEDTLS_ENTROPY_MAX_GATHER, MBEDTLS_ENTROPY_SOURCE_STRONG);
    /* 根据个性化字符串更新种子 */
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t *)pers, strlen(pers));
    assert_exit(ret == 0, ret);

    printf(" ok\n  . Setting up the SSL/TLS structure...");
    /* 加载ssl默认配置选项 */
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    assert_exit(ret == 0, ret);

    /* 设置随机数生成器回调接口 */
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    /* DER格式X.509证书解析 */
    ret = mbedtls_x509_crt_parse_der(&cert, ca_cert_der, ca_cert_der_len);
    assert_exit(ret == 0, ret);

    /* 配置证书链 */
    mbedtls_ssl_conf_ca_chain(&conf, &cert, NULL);
    /* 配置认证模式 */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_THRESHOLD);
    mbedtls_ssl_conf_dbg(&conf, my_debug, NULL);
#endif

    /* 通过配置选项完成ssl的设置 */
    ret = mbedtls_ssl_setup(&ssl, &conf);
    assert_exit(ret == 0, ret);

    /* 配置ssl hostname */
    ret = mbedtls_ssl_set_hostname(&ssl, HOST_NAME);
    assert_exit(ret == 0, ret);

    printf(" ok\n  . Connecting to %s:%s...", SERVER_ADDR, SERVER_PORT);
    /* 建立网络连接 */
    ret = mbedtls_net_connect(&ctx, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
    assert_exit(ret == 0, ret);

    /* 配置网络数据发送和接收回调接口 */
    mbedtls_ssl_set_bio(&ssl, &ctx, mbedtls_net_send, mbedtls_net_recv, NULL);
    
    printf(" ok\n  . Performing the SSL/TLS handshake...");
    /* 执行ssl握手 */
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)    
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
            goto cleanup;
        }
    }
    
    printf(" ok\n  > Write to server:");
    /* 发送ssl应用数据 */
    ret = mbedtls_ssl_write(&ssl, (const uint8_t *)GET_REQUEST, strlen(GET_REQUEST));
    assert_exit(ret > 0, ret);
    len = ret;
    printf(" %d bytes written\n\n%s\n\n", len, GET_REQUEST);

    printf(" > Read from Server:");
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));
    do
    {
        /* 读取ssl应用数据 */
        ret = mbedtls_ssl_read(&ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    assert_exit(ret > 0, ret);
    len = ret;
    printf(" %d bytes read\n\n\n%s\n\n", len, buf);

    /* 通知服务器连接即将关闭 */
    mbedtls_ssl_close_notify(&ssl);
    printf(" ok\n  . Closing the connection ... done\n");

cleanup:
    /* 释放网络结构体 */
    mbedtls_net_free(&ctx);
    /* 释放ssl结构体 */
    mbedtls_ssl_free(&ssl);
    /* 释放ssl配置结构体 */
    mbedtls_ssl_config_free(&conf);
    /* 释放随机数结构体 */
    mbedtls_ctr_drbg_free(&ctr_drbg);
    /* 释放熵结构体 */
    mbedtls_entropy_free(&entropy);
    /* 释放x509证书结构体 */
    mbedtls_x509_crt_free(&cert);
}

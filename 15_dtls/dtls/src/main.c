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
#else
#include <time.h>
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

#if 0
#define SERVER_ADDR "iotwuxi.org"
#define SERVER_PORT "4432"
#define MESSAGE     "Echo this\r\n"
#else
#define SERVER_ADDR "localhost"
#define SERVER_PORT "4432"
#define MESSAGE     "Hello Server!\r\n"
#endif 

/* assert_exit */
#define assert_exit(cond, ret) \
    do { if (!(cond)) { \
        printf("  !. assert: failed [line: %d, error: -0x%04X]\n", __LINE__, -ret); \
        goto cleanup; \
    } } while (0)

/* psk */
const uint8_t psk[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
/* psk identity */
const char psk_id[] = "Client_identity";

/* timer */
struct dtls_timing_context {
    uint32_t snapshot;
    uint32_t int_ms;
    uint32_t fin_ms;
};
static struct dtls_timing_context timer;

/**
 ***********************************************************************************************************************
 * @brief           Set timer
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static void dtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms)
{
    struct dtls_timing_context *ctx = (struct dtls_timing_context *)data;

    ctx->int_ms = int_ms;
    ctx->fin_ms = fin_ms;

    if (fin_ms != 0)
    {
#ifdef CONFIG_ZEPHYR_ENV
        ctx->snapshot = k_uptime_get_32();
#else
        time_t t;
        time(&t);
        ctx->snapshot = t;
        //printf("snapshot=%ld\n", t);
#endif
    }    
}

/**
 ***********************************************************************************************************************
 * @brief           Get delay
 *
 * @param[in]       none
 *
 * @return          none
 ***********************************************************************************************************************
 */
static int dtls_timing_get_delay(void *data)
{
    struct dtls_timing_context *ctx = (struct dtls_timing_context *)data;
    unsigned long elapsed_ms;

    if (ctx->fin_ms == 0)
    {
        return -1;
    }

#ifdef CONFIG_ZEPHYR_ENV
        elapsed_ms = k_uptime_get_32() - ctx->snapshot;
#else
        time_t t;
        time(&t);
        elapsed_ms = t - ctx->snapshot;
#endif

    //printf("elapsed_ms=%ld\n", elapsed_ms);    

    if (elapsed_ms >= ctx->fin_ms)
    {
        return 2;
    }

    if (elapsed_ms >= ctx->int_ms)
    {
        return 1;
    }
    
    return 0;
}

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
    const char *pers = "dtls_client";       /* 个性化字符串 */
    mbedtls_entropy_context entropy;        /* 熵源 */
    mbedtls_ctr_drbg_context ctr_drbg;      /* 随机数 */
    //mbedtls_platform_set_printf(printf);

    mbedtls_ssl_context ssl;                /* 网络结构体 */
    mbedtls_ssl_config conf;                /* ssl结构体 */
    mbedtls_net_context ctx;                /* ssl配置结构体 */
    mbedtls_net_init(&ctx);                 /* 初始化网络结构体 */
    mbedtls_ssl_init(&ssl);                 /* 初始化ssl结构体 */
    mbedtls_ssl_config_init(&conf);         /* 初始化ssl配置结构体 */

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
    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    assert_exit(ret == 0, ret);

    /* 设置随机数生成器回调接口 */
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    /* 配置psk和identity */
    mbedtls_ssl_conf_psk(&conf, psk, sizeof(psk), (const uint8_t *)psk_id, strlen((char*)psk_id));
    /* 通过配置选项完成ssl的设置 */
    ret = mbedtls_ssl_setup(&ssl, &conf);
    assert_exit(ret == 0, ret);

    printf(" ok\n  . Connecting to %s:%s...", SERVER_ADDR, SERVER_PORT);
    /* 建立网络连接 */
    ret = mbedtls_net_connect(&ctx, SERVER_ADDR, SERVER_PORT, MBEDTLS_NET_PROTO_UDP);
    assert_exit(ret == 0, ret);

    /* 设置ssl定时回调接口 */
    mbedtls_ssl_set_timer_cb(&ssl, &timer, dtls_timing_set_delay, dtls_timing_get_delay);
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
    do
    {
        /* 发送ssl应用数据 */
        ret = mbedtls_ssl_write(&ssl, (const uint8_t *)MESSAGE, strlen(MESSAGE));
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    assert_exit(ret > 0, ret);
    len = ret;
    printf(" %d bytes written: %s\n", len, MESSAGE);

    printf(" > Read from Server:");
    len = sizeof(buf) - 1;
    memset(buf, 0, sizeof(buf));
    do
    {
        /* 读取ssl应用数据 */
        ret = mbedtls_ssl_read(&ssl, buf, len);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || MBEDTLS_ERR_SSL_WANT_WRITE);
    assert_exit(ret > 0, ret);
    len = ret;
    printf(" %d bytes read\n\n%s\n", len, buf);

    /* 通知服务器连接即将关闭 */
    mbedtls_ssl_close_notify(&ssl);
    printf(". Closing the connection ... done\n");

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
}

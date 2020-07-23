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
* @file        mbedtls_config.h
*
* @brief       mbedtls_config header file.
*
* @revision
* Date         Author          Notes
* 2020-07-20   XieLi           First Version
***********************************************************************************************************************
*/

#ifndef __MBEDTLS_CONFIG_H_
#define __MBEDTLS_CONFIG_H_

#ifdef __cplusplus
extern "C"{
#endif

/* System support */
/* 启用平台抽象接口 */
#define MBEDTLS_PLATFORM_C
/* 启用内存分配接口 */
#define MBEDTLS_PLATFORM_MEMORY
/* 启用mbedtls自带的内存分配接口 */
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C
/* 不使用标准库函数 */
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
/* 使能exit接口替换 */
#define MBEDTLS_PLATFORM_EXIT_ALT
/* 不使用内置的熵源 */
#define MBEDTLS_NO_PLATFORM_ENTROPY
/* 取消默认熵源功能 */
#define MBEDTLS_NO_DEFAULT_ENTROPY_SOURCES
/* 使能printf接口替换 */
#define MBEDTLS_PLATFORM_PRINTF_ALT

/* mbed TLS modules */
/* 启用base64功能 */
#define MBEDTLS_BASE64_C

/* 配置文件检查 */
#include "mbedtls/check_config.h"

#ifdef __cplusplus
}
#endif

#endif  /* __MBEDTLS_CONFIG_H_ */
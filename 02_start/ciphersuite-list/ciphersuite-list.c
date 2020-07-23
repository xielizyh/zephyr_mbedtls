/**
  ******************************************************************************
  * @file			ciphersuite-list.c
  * @brief			ciphersuite-list function
  * @author			Xli
  * @email			xieliyzh@163.com
  * @version		1.0.0
  * @date			2020-07-07
  * @copyright		2020, CMIoT Co.,Ltd. All rights reserved
  ******************************************************************************
**/

/* Includes ------------------------------------------------------------------*/
#include <stdio.h>
#include <stdint.h>

#include "mbedtls/ssl.h"
/* Private constants ---------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
#define mbedtls_printf  printf

/* Private typedef -----------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function ----------------------------------------------------------*/

/**=============================================================================
 * @brief           main
 *
 * @param[in]       none
 *
 * @return          0
 *============================================================================*/
int main(void)
{
    const int* list;
    const char* name;
    int index = 1;
    
    mbedtls_printf("\n\t Available Ciphersuite:\t\n");
    list = mbedtls_ssl_list_ciphersuites();
    for (; *list; list++)
    {
        name = mbedtls_ssl_get_ciphersuite_name(*list);
        mbedtls_printf("\t[%03d]\t%s\n", index++, name);
    }
    mbedtls_printf("\n");

    return 0;
}
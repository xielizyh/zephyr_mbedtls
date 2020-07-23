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

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "mbedtls/bignum.h"
#include "mbedtls/platform.h"

/**=============================================================================
 * @brief           打印
 *
 * @param[in]       none
 *
 * @return          none
 *============================================================================*/
static void dump_buf(char *buf, size_t len) 
{
    for (int i = 0; i < len; i++) 
    {
        printf("%c%s", buf[i], 
                        (i + 1) % 32 ? "" : "\n\t"); 
    }
    printf("\n");
}

/**=============================================================================
 * @brief           main
 *
 * @param[in]       none
 *
 * @return          0
 *============================================================================*/
void main(void)
{
    size_t olen;
    char buf[256];
    mbedtls_mpi A, E, N, X;

    //mbedtls_platform_set_printf(printf);

    mbedtls_mpi_init(&A); 
    mbedtls_mpi_init(&E); 
    mbedtls_mpi_init(&N); 
    mbedtls_mpi_init(&X);

    mbedtls_mpi_read_string(&A, 16,
        "EFE021C2645FD1DC586E69184AF4A31E" \
        "D5F53E93B5F123FA41680867BA110131" \
        "944FE7952E2517337780CB0DB80E61AA" \
        "E7C8DDC6C5C6AADEB34EB38A2F40D5E6" );

    mbedtls_mpi_read_string(&E, 16,
        "B2E7EFD37075B9F03FF989C7C5051C20" \
        "34D2A323810251127E7BF8625A4F49A5" \
        "F3E27F4DA8BD59C47D6DAABA4C8127BD" \
        "5B5C25763222FEFCCFC38B832366C29E" );

    mbedtls_mpi_read_string(&N, 16,
        "0066A198186C18C10B2F5ED9B522752A" \
        "9830B69916E535C8F047518A889A43A5" \
        "94B6BED27A168D31D4A52F88925AA8F5" );

    mbedtls_mpi_mul_mpi(&X, &A, &N);
    mbedtls_mpi_write_string(&X, 16, buf, 256, &olen);
    mbedtls_printf("\n  X = A * N = \n\t");
    dump_buf(buf, olen);

    mbedtls_mpi_exp_mod(&X, &A, &E, &N, NULL);
    mbedtls_mpi_write_string(&X, 16, buf, 256, &olen);
    mbedtls_printf("\n  X = A^E mode N = \n\t");
    dump_buf(buf, olen);

    mbedtls_mpi_inv_mod( &X, &A, &N);
    mbedtls_mpi_write_string(&X, 16, buf, 256, &olen);
    mbedtls_printf("\n  X = A^-1 mod N = \n\t");
    dump_buf(buf, olen);

    mbedtls_mpi_free(&A); 
    mbedtls_mpi_free(&E);
    mbedtls_mpi_free(&N); 
    mbedtls_mpi_free(&X);

    //return 0;   
}
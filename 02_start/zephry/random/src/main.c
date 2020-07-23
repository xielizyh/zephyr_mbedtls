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
#include <random/rand32.h>
#include <stdio.h>

void main(void)
{
    k_timeout_t timeout = {.ticks=100};
    printf("\n\t%s board random:\n", CONFIG_BOARD);
    while (1)
    {
        printf("\t0x%08x\n", sys_rand32_get());
        k_sleep(timeout);
    }
}
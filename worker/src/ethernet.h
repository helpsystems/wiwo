/*
 *
 * Copyright 2003-2015 CORE Security Technologies
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Authors:
 *          Andres Blanco (6e726d)
 *          Andres Gazzoli
 *
 */

#ifndef _ETHERNET_H_
#define _ETHERNET_H_

#include "mac.h"

#define ETHERNET_ADDR_LEN MAC_ADDR_LEN
#define ETHERNET_STR_ADDR_LEN MAC_STR_ADDR_LEN

#define ETHERNET_MTU 1500
#define ETHERNET_TYPE_LEN 2
#define ETHERNET_HDR_SIZE 14
#define ETHERNET_MIN_SIZE 64
#define ETHERNET_DATA_MIN_LEN (ETHERNET_MIN_SIZE - ETHERNET_HDR_SIZE)

struct ethernet_header
{
    unsigned char  destination[ETHERNET_ADDR_LEN];
    unsigned char  source[ETHERNET_ADDR_LEN];
    unsigned short type;
};

#endif /* _ETHERNET_H_ */

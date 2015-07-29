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

#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "network.h"

#define WIWO_ETHERNET_TYPE 0xFAFA
#define WIWO_ETHERNET_HDR_MIN_SIZE (ETHERNET_HDR_SIZE + 1)
#define WIWO_ETHERNET_HDR_FRAG_SIZE (WIWO_ETHERNET_HDR_MIN_SIZE + 1)

#define TYPE_ACK            0x00
#define TYPE_ANNOUNCE       0x01
#define TYPE_INFO_REQUEST   0x02
#define TYPE_INFO_RESPONSE  0x03
#define TYPE_SET_CHANNEL    0x04
#define TYPE_START          0x05
#define TYPE_STOP           0x06
#define TYPE_DATA           0x07
#define TYPE_DATA_FRAGMENT  0x08
#define TYPE_DATA_INJECT    0x09
#define TYPE_ERROR          0x0A

#define SEQUENCE_NUMBER_MASK 0x7F
#define LAST_FRAGMENT_MASK   0x80

#endif /* _PROTOCOL_H_ */

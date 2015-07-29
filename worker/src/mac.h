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

#ifndef _MAC_H_
#define _MAC_H_

#define MAC_ADDR_LEN 6
#define MAC_STR_ADDR_LEN 17

// Returns a binary representation of a string MAC address.
int get_mac_address_from_string(const char*, unsigned char*);

// Returns a binary representation of the MAC address for an interface.
int get_mac_address_from_iface(const char*, unsigned char*);

// Returns string representation of the MAC address for an interface.
int get_string_mac_address_for_iface(const char*, char*);

// Return string representation of a MAC address.
int get_string_mac_address(const unsigned char*, char*);


#endif /* _MAC_H_ */

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

#include "mac.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>

/*
 * Returns a binary representation of the string MAC address in
 * parameter smaddr. On success zero is returned.
 */
int get_mac_address_from_string(const char* smaddr, unsigned char* maddr)
{
    size_t smaddr_idx = 0;
    size_t maddr_idx = 0;

    if(strlen(smaddr) != MAC_STR_ADDR_LEN)
        return -1;

    for(smaddr_idx = 0; smaddr_idx < MAC_STR_ADDR_LEN; smaddr_idx += 3)
    {
        char aux[3] = {0};
        memcpy(aux, smaddr + smaddr_idx, 2);
        maddr[maddr_idx] = (unsigned char)strtol(aux, NULL, 16);
        maddr_idx += 1;
    }

    return 0;
}

/*
 * Returns the binary representation of the MAC address of iface_name on the
 * addr variable. On success zero is returned.
 */
int get_mac_address_from_iface(const char* iface_name, unsigned char* addr)
{
    int sd;
    struct ifreq ifr;
    size_t iface_name_len;

    iface_name_len = strlen(iface_name);
    if(iface_name_len < sizeof(ifr.ifr_name))
    {
        memcpy(ifr.ifr_name, iface_name, iface_name_len);
        ifr.ifr_name[iface_name_len] = 0;
    }
    else
        return -1;

    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sd == -1)
        return -1;

    if(ioctl(sd, SIOCGIFHWADDR, &ifr) == -1)
    {
        close(sd);
        return -1;
    }
    close(sd);

    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
    {
        return -1;
    }

    memcpy(addr, ifr.ifr_hwaddr.sa_data, MAC_ADDR_LEN);

    return 0;
}

/*
 * Returns string representation of the MAC address for an interface.
 */
int get_string_mac_address_for_iface(const char* iface_name, char* mac_addr_s)
{
    unsigned char* mac_addr;

    mac_addr = (unsigned char*)malloc(MAC_ADDR_LEN);

    if(get_mac_address_from_iface(iface_name, mac_addr) == -1)
        return -1;

    if(get_string_mac_address(mac_addr, mac_addr_s) == -1)
    {
        free(mac_addr);
        return -1;
    }

    free(mac_addr);

    return 0;

}

/*
 * Returns string representation of a MAC address.
 */
int get_string_mac_address(const unsigned char* mac_addr, char* mac_addr_s)
{
    if(sprintf(mac_addr_s,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        mac_addr[0], mac_addr[1], mac_addr[2],
        mac_addr[3], mac_addr[4], mac_addr[5]) != 17)
        return -1;
    return 0;
}

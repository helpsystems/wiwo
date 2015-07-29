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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <linux/wireless.h>

#include "network.h"
#include "ethernet.h"
#include "wireless.h"

/*
 * Returns wireless interface protocol name on protocol_name parameter.
 * On success zero is returned.
 */
int get_wireless_iface_protocol(const char* interface_name,
                                char* protocol_name)
{
    int sd;
    struct iwreq wrq;

    if(interface_name == NULL || protocol_name == NULL)
        return -1;

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ);
 
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    if(ioctl(sd, SIOCGIWNAME, &wrq) != -1)
    {
        strncpy(protocol_name, wrq.u.name, IFNAMSIZ);
        close(sd);
        return 0;
    }

    close(sd);
    return -1;
}

/*
 * Returns wireless inferface mode on mode parameter. On success zero
 * is returned.
 */
int get_wireless_iface_mode(const char* interface_name, char* mode)
{
    int sd;
    struct iwreq wrq;

    if(interface_name == NULL || mode == NULL)
        return -1;

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ);
 
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    if(ioctl(sd, SIOCGIWMODE, &wrq) != -1)
    {
        switch(wrq.u.mode)
        {
            case IW_MODE_AUTO:
                sprintf(mode, MODE_AUTO);
                break;
            case IW_MODE_ADHOC:
                sprintf(mode, MODE_ADHOC);
                break;
            case IW_MODE_INFRA:
                sprintf(mode, MODE_INFRA);
                break;
            case IW_MODE_MASTER:
                sprintf(mode, MODE_MASTER);
                break;
            case IW_MODE_REPEAT:
                sprintf(mode, MODE_REPEAT);
                break;
            case IW_MODE_SECOND:
                sprintf(mode, MODE_SECOND);
                break;
            case IW_MODE_MONITOR:
                sprintf(mode, MODE_MONITOR);
                break;
            case IW_MODE_MESH:
                sprintf(mode, MODE_MESH);
                break;
            default:
                close(sd);
                return -1;
        }
        close(sd);
        return 0;
    }

    close(sd);
    return -1;
}

/*
 * Returns wireless inferface frequency on freq parameter. On success
 * zero is returned.
 */
int get_wireless_iface_freq(const char* interface_name,
                            unsigned short int* freq)
{
    int sd;
    struct iwreq wrq;

    if(interface_name == NULL || freq == NULL)
        return -1;

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ);
 
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    if(ioctl(sd, SIOCGIWFREQ, &wrq) != -1)
    {
        *freq = wrq.u.freq.m;
        close(sd);
        return 0;
    }

    close(sd);
    return -1;
}

/*
 * Set wireless interface channel defined on channel parameter. On success
 * zero is returned.
 */
int set_wireless_iface_channel(const char* interface_name,
                               const unsigned char channel)
{
    int sd;
    struct iwreq wrq;

    if(interface_name == NULL || channel == 0)
        return -1;

    memset(&wrq, 0, sizeof(wrq));
    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ);
 
    if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    wrq.u.freq.m = channel;

    if(ioctl(sd, SIOCSIWFREQ, &wrq) != -1)
    {
        close(sd);
        return 0;
    }

    close(sd);
    return -1;
}

/*
 * Returns wireless channels on channels parameter supported by the interface
 * defined on interface_name parameter. On success zero is returned.
 */
int get_wireless_iface_supported_channels(const char *interface_name,
                                          unsigned char* num_channels,
                                          unsigned char* channels)
{
    int i;
    int sd = NULL;
    struct iwreq wrq;
    char buffer[sizeof(struct iw_range) * 2];

    memset(buffer, 0, sizeof(buffer));
    memset(&wrq, 0, sizeof(struct iwreq));

    wrq.u.data.pointer = buffer;
    wrq.u.data.length = sizeof(buffer);
    wrq.u.data.flags = 0;

    strncpy(wrq.ifr_name, interface_name, IFNAMSIZ);

    sd = socket(AF_INET, SOCK_DGRAM, 0);

    if(sd == -1)
        return -1;

    if(ioctl(sd, SIOCGIWRANGE, &wrq) >= 0)
    {
        struct iw_range *range = (struct iw_range *)buffer;

        *num_channels = range->num_frequency;
        for(i = 0; i < range->num_frequency; i++)
            memcpy(channels + i, &range->freq[i].i, 1);
    }

    close(sd);

    return 0;
}

/*
 * Returns wireless channel for the frequency parameter.
 */
unsigned char get_channel_from_frequency(unsigned short int frequency)
{
    if(frequency >= BG_LOWER_FREQUENCY && frequency <= BG_UPPER_FREQUENCY)
        return (frequency - BG_BASE_FREQUENCY) / FREQUENCY_DELTA;
    else if(frequency == BG_CH14_FREQUENCY)
        return 14;
    else if(frequency >= A_LOWER_FREQUENCY && frequency <= A_UPPER_FREQUENCY)
        return (frequency - A_BASE_FREQUENCY) / FREQUENCY_DELTA;
    return 0;
}

/*
 * Returns a buffer containing information of the wireless interfaces
 * of the local system. The information is stored in the following
 * structure.
 * 
 *  1B length
 *  NB data
 * 
 * The information contains the interface name, protocol and
 * supported channels.
 * 
 * On success zero is returned.
 */
int get_wireless_interfaces_information(unsigned char* information_buffer,
                                        unsigned short int* info_buffer_length)
{
    struct ifaddrs *ifaddr, *ifa;
    unsigned short int offset = 0;

    if(getifaddrs(&ifaddr) == -1)
        return -1;

    for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        char protocol_name[254];

        if(ifa->ifa_addr == NULL ||
           ifa->ifa_addr->sa_family != AF_PACKET)
            continue;
 
        if(get_wireless_iface_protocol(ifa->ifa_name, protocol_name) == 0)
        {
            unsigned char channel;
            unsigned short int freq;

            struct lv protocol_name_lv;
            struct lv interface_name_lv;

            unsigned char num_channels = 0;
            unsigned char sup_channels[255];

            if(offset >= ETHERNET_MTU)
                break;

            if(get_wireless_iface_freq(ifa->ifa_name, &freq) != 0)
                break;
            channel = get_channel_from_frequency(freq);

            memset(sup_channels, 0, sizeof(sup_channels));
            memset(&interface_name_lv, 0, sizeof(interface_name_lv));
            memset(&protocol_name_lv, 0, sizeof(protocol_name_lv));

            interface_name_lv.length = (unsigned char)strlen(ifa->ifa_name);
            memcpy(interface_name_lv.value,
                   ifa->ifa_name,
                   interface_name_lv.length);
            memcpy(information_buffer + offset,
                   &interface_name_lv,
                   interface_name_lv.length + 1);
            offset += interface_name_lv.length + 1;

            protocol_name_lv.length = (unsigned char)strlen(protocol_name);
            memcpy(protocol_name_lv.value,
                   protocol_name,
                   protocol_name_lv.length);
            memcpy(information_buffer + offset,
                   &protocol_name_lv,
                   protocol_name_lv.length + 1);
            offset += protocol_name_lv.length + 1;

            get_wireless_iface_supported_channels(ifa->ifa_name,
                                                  &num_channels,
                                                  sup_channels);
            memcpy(information_buffer + offset,
                   &num_channels,
                   sizeof(num_channels));
            offset += sizeof(num_channels);
            memcpy(information_buffer + offset, sup_channels, num_channels);
            offset += num_channels;

            memcpy(information_buffer + offset, &channel, sizeof(channel));
            offset += sizeof(channel);
        }
    }

    *info_buffer_length = offset;

    freeifaddrs(ifaddr);

    return 0;
}
